from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.ml.pipeline import run_detection


def build_investigation_graph(db: Session) -> nx.DiGraph:
    """
    Build a real, consistent, deterministic directed entity relationship graph from TRACE-X database.
    Relationships:
    - Wallet --[spends]--> Transaction (via transaction_inputs)
    - Transaction --[receives]--> Wallet (via transaction_outputs)
    - Src IP --[relayed_by]--> Transaction (via network_observations)
    - Transaction --[propagated_to]--> Dst IP (via network_observations)
    """
    graph = nx.DiGraph()

    # Pre-fetch ML detection results for wallet risk scoring
    ml_results = run_detection()
    wallet_risk_map = {}
    wallet_anomaly_map = {}
    if ml_results is not None and not ml_results.empty:
        for _, row in ml_results.iterrows():
            w_addr = str(row["wallet_address"])
            wallet_risk_map[w_addr] = round(float(row.get("risk_score", 0.0)), 1)
            wallet_anomaly_map[w_addr] = bool(row.get("anomaly_label", 1) == -1)

    # 1. Wallets
    wallets_data = db.execute(
        text("""
            SELECT
                address,
                transaction_count,
                total_received,
                total_sent
            FROM wallets
        """)
    ).mappings().all()

    for w in wallets_data:
        addr = str(w["address"])
        risk = wallet_risk_map.get(addr, 0.0)
        is_anom = wallet_anomaly_map.get(addr, False)
        graph.add_node(
            addr,
            id=addr,
            type="wallet",
            label=f"{addr[:6]}...{addr[-4:]}",
            transaction_count=int(w["transaction_count"] or 0),
            total_received=round(float(w["total_received"] or 0), 4),
            total_sent=round(float(w["total_sent"] or 0), 4),
            risk_score=risk,
            is_risk=risk >= 60.0,
            anomaly_status="ANOMALOUS" if is_anom else "NORMAL",
            connected_ips=0,
            connected_txs=0
        )

    # 2. Transactions
    tx_data = db.execute(
        text("""
            SELECT
                t.txid,
                t.timestamp,
                t.fee,
                t.script_type,
                COALESCE((SELECT SUM(amount) FROM transaction_outputs WHERE txid = t.txid), 0) AS total_value,
                COALESCE((SELECT COUNT(*) FROM transaction_inputs WHERE txid = t.txid), 0) AS input_count,
                COALESCE((SELECT COUNT(*) FROM transaction_outputs WHERE txid = t.txid), 0) AS output_count
            FROM transactions t
        """)
    ).mappings().all()

    for t in tx_data:
        txid = str(t["txid"])
        total_val = round(float(t["total_value"] or 0), 4)
        in_cnt = int(t["input_count"] or 0)
        out_cnt = int(t["output_count"] or 0)
        # Approximate transaction risk level based on fanout, inputs, value
        tx_risk = min(100.0, max(15.0, (out_cnt * 8.0) + (in_cnt * 5.0) + (min(total_val, 20.0) * 2.0)))
        graph.add_node(
            txid,
            id=txid,
            type="transaction",
            label=f"{txid[:6]}...{txid[-4:]}",
            timestamp=str(t["timestamp"]),
            fee=round(float(t["fee"] or 0), 6),
            script_type=str(t["script_type"] or "P2WPKH"),
            amount=total_val,
            input_count=in_cnt,
            output_count=out_cnt,
            risk_score=round(tx_risk, 1),
            is_risk=tx_risk >= 60.0
        )

    # 3. IP Addresses
    ip_data = db.execute(
        text("""
            SELECT
                address,
                country,
                asn,
                observation_count
            FROM ip_addresses
        """)
    ).mappings().all()

    for ip in ip_data:
        addr = str(ip["address"])
        graph.add_node(
            addr,
            id=addr,
            type="ip",
            label=addr,
            country=str(ip["country"] or "Unknown"),
            asn=str(ip["asn"] or "Unknown"),
            observation_count=int(ip["observation_count"] or 0),
            connected_wallets=0,
            connected_txs=0
        )

    # 4. Inputs: Wallet spends in Transaction (Wallet -> Transaction)
    inputs_data = db.execute(
        text("""
            SELECT wallet_address, txid, amount
            FROM transaction_inputs
        """)
    ).mappings().all()

    for row in inputs_data:
        w_addr = str(row["wallet_address"])
        txid = str(row["txid"])
        amt = round(float(row["amount"] or 0), 6)

        if w_addr not in graph:
            graph.add_node(w_addr, id=w_addr, type="wallet", label=f"{w_addr[:6]}...{w_addr[-4:]}", risk_score=0.0)
        if txid not in graph:
            graph.add_node(txid, id=txid, type="transaction", label=f"{txid[:6]}...{txid[-4:]}", risk_score=0.0)

        edge_key = f"{w_addr}->{txid}:spends"
        if not graph.has_edge(w_addr, txid):
            graph.add_edge(
                w_addr,
                txid,
                id=edge_key,
                relationship="spends",
                amount=amt,
                label=f"Spends {amt} BTC"
            )

    # 5. Outputs: Transaction pays Wallet (Transaction -> Wallet)
    outputs_data = db.execute(
        text("""
            SELECT txid, wallet_address, amount
            FROM transaction_outputs
        """)
    ).mappings().all()

    for row in outputs_data:
        txid = str(row["txid"])
        w_addr = str(row["wallet_address"])
        amt = round(float(row["amount"] or 0), 6)

        if txid not in graph:
            graph.add_node(txid, id=txid, type="transaction", label=f"{txid[:6]}...{txid[-4:]}", risk_score=0.0)
        if w_addr not in graph:
            graph.add_node(w_addr, id=w_addr, type="wallet", label=f"{w_addr[:6]}...{w_addr[-4:]}", risk_score=0.0)

        edge_key = f"{txid}->{w_addr}:receives"
        if not graph.has_edge(txid, w_addr):
            graph.add_edge(
                txid,
                w_addr,
                id=edge_key,
                relationship="receives",
                amount=amt,
                label=f"Receives {amt} BTC"
            )

    # 6. Network Observations:
    # Src IP -> Transaction (relayed_by)
    # Transaction -> Dst IP (propagated_to)
    obs_data = db.execute(
        text("""
            SELECT src_ip, dst_ip, txid, geo_country, asn
            FROM network_observations
            WHERE txid IS NOT NULL
        """)
    ).mappings().all()

    for obs in obs_data:
        src = str(obs["src_ip"])
        dst = str(obs["dst_ip"])
        txid = str(obs["txid"])

        if src not in graph:
            graph.add_node(src, id=src, type="ip", label=src)
        if dst not in graph:
            graph.add_node(dst, id=dst, type="ip", label=dst)
        if txid not in graph:
            graph.add_node(txid, id=txid, type="transaction", label=f"{txid[:6]}...{txid[-4:]}")

        # Edge 1: src -> txid
        src_edge = f"{src}->{txid}:relayed_by"
        if not graph.has_edge(src, txid):
            graph.add_edge(
                src,
                txid,
                id=src_edge,
                relationship="relayed_by",
                label="Relayed by peer"
            )

        # Edge 2: txid -> dst
        dst_edge = f"{txid}->{dst}:propagated_to"
        if not graph.has_edge(txid, dst):
            graph.add_edge(
                txid,
                dst,
                id=dst_edge,
                relationship="propagated_to",
                label="Propagated to peer"
            )

    # Compute graph degrees for IP and wallet metrics
    for n, d in graph.nodes(data=True):
        if d.get("type") == "ip":
            connected = list(graph.predecessors(n)) + list(graph.successors(n))
            d["connected_txs"] = len([x for x in connected if graph.nodes[x].get("type") == "transaction"])
            d["connected_wallets"] = len([x for x in connected if graph.nodes[x].get("type") == "wallet"])
        elif d.get("type") == "wallet":
            connected = list(graph.predecessors(n)) + list(graph.successors(n))
            d["connected_txs"] = len([x for x in connected if graph.nodes[x].get("type") == "transaction"])
            # Counterparty wallets
            counterparties = set()
            for tx in connected:
                if graph.nodes[tx].get("type") == "transaction":
                    for other in list(graph.predecessors(tx)) + list(graph.successors(tx)):
                        if other != n and graph.nodes[other].get("type") == "wallet":
                            counterparties.add(other)
            d["connected_wallets_count"] = len(counterparties)

    return graph


def compute_graph_synopsis(graph: nx.DiGraph) -> Dict[str, Any]:
    """Calculate real dataset-level graph metrics."""
    if not graph or graph.number_of_nodes() == 0:
        return {
            "total_nodes": 0,
            "total_edges": 0,
            "wallets": 0,
            "transactions": 0,
            "ips": 0,
            "high_risk_wallets": 0,
            "high_risk_transactions": 0,
            "network_density": 0.0,
            "clusters": 0,
            "largest_component": 0
        }

    wallets = [n for n, d in graph.nodes(data=True) if d.get("type") == "wallet"]
    txs = [n for n, d in graph.nodes(data=True) if d.get("type") == "transaction"]
    ips = [n for n, d in graph.nodes(data=True) if d.get("type") == "ip"]

    high_risk_wallets = sum(1 for w in wallets if graph.nodes[w].get("risk_score", 0.0) >= 60.0)
    high_risk_txs = sum(1 for t in txs if graph.nodes[t].get("risk_score", 0.0) >= 60.0)

    # Undirected components
    undirected = graph.to_undirected(as_view=True)
    components = list(nx.connected_components(undirected))
    clusters_cnt = len(components)
    largest_comp = max((len(c) for c in components), default=0)
    density = round(float(nx.density(graph)), 5)

    return {
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
        "wallets": len(wallets),
        "transactions": len(txs),
        "ips": len(ips),
        "high_risk_wallets": high_risk_wallets,
        "high_risk_transactions": high_risk_txs,
        "network_density": density,
        "clusters": clusters_cnt,
        "largest_component": largest_comp
    }


def get_deterministic_focused_graph(
    graph: nx.DiGraph,
    focus_wallet: Optional[str] = None,
    max_nodes: int = 150,
    scope: str = "focused"
) -> Dict[str, Any]:
    """
    Extract a deterministic, reproducible sub-neighborhood around the focus entity,
    or a global prioritized representation across the entire dataset.
    Guarantees stable node ordering, stable edge IDs, and zero phantom links.
    """
    synopsis = compute_graph_synopsis(graph)

    if not graph or graph.number_of_nodes() == 0:
        return {"wallet": focus_wallet, "nodes": [], "edges": [], "synopsis": synopsis}

    undirected = graph.to_undirected(as_view=True)
    neighborhood: Set[str] = set()

    if scope == "all" or focus_wallet in ("ALL_DATASET", "GLOBAL", "all", ""):
        # Global prioritized sampling: High risk nodes + hubs + connected infrastructure
        candidates = sorted(
            list(graph.nodes(data=True)),
            key=lambda x: (
                -float(x[1].get("risk_score", 0.0)),
                -int(x[1].get("transaction_count", 0)),
                -int(x[1].get("observation_count", 0)),
                str(x[0])
            )
        )
        for n_id, _ in candidates[:max_nodes]:
            neighborhood.add(n_id)
        focus_wallet = candidates[0][0] if candidates else None
    else:
        # If focus entity is not specified or not in graph, select the highest risk wallet
        if not focus_wallet or focus_wallet not in graph:
            wallet_candidates = [
                (n, d.get("risk_score", 0.0), d.get("transaction_count", 0))
                for n, d in graph.nodes(data=True)
                if d.get("type") == "wallet"
            ]
            if wallet_candidates:
                wallet_candidates.sort(key=lambda x: (-x[1], -x[2], x[0]))
                focus_wallet = wallet_candidates[0][0]
            else:
                first_node = sorted(list(graph.nodes()))[0]
                focus_wallet = first_node

        if focus_wallet not in graph:
            return {"wallet": focus_wallet, "nodes": [], "edges": [], "synopsis": synopsis}

        # Hop 0: Center entity
        neighborhood.add(focus_wallet)

        # Hop 1: Directly connected neighbors
        hop1 = sorted(list(undirected.neighbors(focus_wallet)))
        neighborhood.update(hop1)

        # Hop 2: Secondary neighbors (sorted deterministically)
        hop2_candidates: List[Tuple[float, str]] = []
        for n in hop1:
            for neighbor in undirected.neighbors(n):
                if neighbor not in neighborhood:
                    n_data = graph.nodes[neighbor]
                    score = n_data.get("risk_score", 0.0)
                    hop2_candidates.append((score, neighbor))

        hop2_candidates.sort(key=lambda x: (-x[0], x[1]))

        for _, n_id in hop2_candidates:
            if len(neighborhood) >= max_nodes:
                break
            neighborhood.add(n_id)

    # Deterministic node serialization
    nodes_list = []
    sorted_node_ids = sorted(
        list(neighborhood),
        key=lambda x: (graph.nodes[x].get("type", ""), -float(graph.nodes[x].get("risk_score", 0.0)), str(x))
    )

    for node_id in sorted_node_ids:
        d = graph.nodes[node_id]
        nodes_list.append({
            "id": str(node_id),
            "type": d.get("type", "unknown"),
            "label": d.get("label", str(node_id)),
            "risk_score": float(d.get("risk_score", 0.0)),
            "is_risk": bool(d.get("is_risk", False)),
            "anomaly_status": d.get("anomaly_status", "NORMAL"),
            "transaction_count": int(d.get("transaction_count", 0)),
            "total_received": float(d.get("total_received", 0.0)),
            "total_sent": float(d.get("total_sent", 0.0)),
            "amount": float(d.get("amount", 0.0)),
            "fee": float(d.get("fee", 0.0)),
            "timestamp": str(d.get("timestamp", "")),
            "script_type": str(d.get("script_type", "")),
            "input_count": int(d.get("input_count", 0)),
            "output_count": int(d.get("output_count", 0)),
            "country": str(d.get("country", "")),
            "asn": str(d.get("asn", "")),
            "observation_count": int(d.get("observation_count", 0)),
            "connected_txs": int(d.get("connected_txs", 0)),
            "connected_wallets_count": int(d.get("connected_wallets_count", d.get("connected_wallets", 0))),
            "is_focus": (node_id == focus_wallet)
        })

    # Deterministic edge serialization
    edges_list = []
    seen_edge_ids = set()

    for u in sorted_node_ids:
        for v in sorted(list(graph.successors(u))):
            if v in neighborhood:
                e_data = graph.get_edge_data(u, v)
                rel = e_data.get("relationship", "related")
                edge_id = f"{u}->{v}:{rel}"
                if edge_id not in seen_edge_ids:
                    seen_edge_ids.add(edge_id)
                    edges_list.append({
                        "id": edge_id,
                        "source": str(u),
                        "target": str(v),
                        "relationship": rel,
                        "amount": e_data.get("amount", None),
                        "label": e_data.get("label", "")
                    })

    return {
        "wallet": focus_wallet,
        "nodes": nodes_list,
        "edges": edges_list,
        "synopsis": synopsis,
        "meta": {
            "total_nodes": len(nodes_list),
            "total_edges": len(edges_list),
            "focus_type": graph.nodes[focus_wallet].get("type", "wallet") if focus_wallet and focus_wallet in graph else "wallet"
        }
    }
