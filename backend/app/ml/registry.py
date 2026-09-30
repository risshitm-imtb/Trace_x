import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


BASE_DIR = Path(__file__).resolve().parents[3]
REGISTRY_FILE = BASE_DIR / "models" / "registry.json"


class ModelMetadata(BaseModel):
    model_id: str
    name: str
    purpose: str
    algorithm: str
    version: str
    features: List[str]
    artifact_path: str
    status: str = "ACTIVE"
    trained_at: Optional[str] = None
    sample_count: int = 0
    metrics: Dict[str, Any] = {}


DEFAULT_MODELS: Dict[str, Dict[str, Any]] = {
    "wallet_anomaly": {
        "model_id": "wallet_anomaly",
        "name": "Wallet Behavioral Anomaly Detector",
        "purpose": "Detects anomalous wallet velocity, flow imbalance, and network infrastructure diversity",
        "algorithm": "Isolation Forest (300 estimators)",
        "version": "1.2.0",
        "features": [
            "transaction_count", "total_received", "total_sent",
            "input_tx_count", "output_tx_count", "source_ip_count",
            "destination_ip_count", "asn_count", "tx_per_ip",
            "flow_imbalance", "network_diversity"
        ],
        "artifact_path": "models/wallet_anomaly_model.joblib",
        "status": "ACTIVE",
        "metrics": {"contamination": 0.08, "n_estimators": 300}
    },
    "transaction_risk": {
        "model_id": "transaction_risk",
        "name": "Transaction Anomaly & Risk Scorer",
        "purpose": "Evaluates transaction-level outlier scores, fan-out ratios, and fee-to-value anomalies",
        "algorithm": "Isolation Forest + Heuristic Risk Scorer",
        "version": "1.1.0",
        "features": [
            "total_input", "total_output", "fee", "fee_ratio",
            "input_count", "output_count", "fanout_ratio", "value_per_output"
        ],
        "artifact_path": "models/transaction_anomaly_model.joblib",
        "status": "ACTIVE",
        "metrics": {"contamination": 0.05, "n_estimators": 200}
    },
    "network_anomaly": {
        "model_id": "network_anomaly",
        "name": "Network Propagation Anomaly Model",
        "purpose": "Identifies peer-to-peer relay anomalies, autonomous system concentration, and unusual IP pairing",
        "algorithm": "Isolation Forest (Network Observation Density)",
        "version": "1.0.0",
        "features": [
            "src_ip_freq", "dst_ip_freq", "asn_freq", "country_entropy",
            "src_port_bucket", "dst_port"
        ],
        "artifact_path": "models/network_anomaly_model.joblib",
        "status": "ACTIVE",
        "metrics": {"contamination": 0.06, "n_estimators": 150}
    },
    "behavior_clustering": {
        "model_id": "behavior_clustering",
        "name": "Entity Behavioral Archetype Discovery",
        "purpose": "Unsupervised clustering classifying entities into behavioral archetypes (Retail, Velocity, Peel, Mix, Vault)",
        "algorithm": "MiniBatchKMeans (k=5 clusters)",
        "version": "1.0.0",
        "features": [
            "transaction_count", "tx_per_ip", "network_diversity",
            "flow_imbalance", "total_received"
        ],
        "artifact_path": "models/behavior_clustering_model.joblib",
        "status": "ACTIVE",
        "metrics": {"k_clusters": 5, "archetypes": ["Retail P2P", "High Velocity Relay", "Peeling Chain", "Mixing Pool", "Consolidator Vault"]}
    },
    "risk_classifier": {
        "model_id": "risk_classifier",
        "name": "Multi-Vector Risk Fusion Engine",
        "purpose": "Fuses behavioral anomalies, structural fan-out, velocity, and network diversity into continuous risk scores and priority tiers",
        "algorithm": "Multi-Vector Ensemble Scoring & Priority Calibration",
        "version": "1.2.0",
        "features": [
            "anomaly_component", "velocity_component", "network_component",
            "flow_component", "fanout_signal", "reuse_signal"
        ],
        "artifact_path": "models/risk_scoring_engine.json",
        "status": "ACTIVE",
        "metrics": {"risk_weights": {"anomaly": 0.50, "velocity": 0.20, "network": 0.15, "flow": 0.15}}
    }
}


class ModelRegistry:
    def __init__(self):
        self._models: Dict[str, ModelMetadata] = {}
        self._load()

    def _load(self):
        REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        if REGISTRY_FILE.exists():
            try:
                with open(REGISTRY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for k, v in data.items():
                        self._models[k] = ModelMetadata(**v)
            except Exception as e:
                print(f"Warning: Failed to load model registry: {e}")

        # Ensure defaults are registered if missing
        for mid, mdata in DEFAULT_MODELS.items():
            if mid not in self._models:
                mdata_copy = dict(mdata)
                artifact_full = BASE_DIR / mdata_copy.get("artifact_path", "")
                is_active = artifact_full.exists()
                mdata_copy["status"] = "ACTIVE" if is_active else "UNTRAINED"
                mdata_copy["trained_at"] = datetime.now().isoformat(timespec="seconds") if is_active else None
                self._models[mid] = ModelMetadata(**mdata_copy)

    def save(self):
        REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(REGISTRY_FILE, "w", encoding="utf-8") as f:
            json.dump({k: v.model_dump() for k, v in self._models.items()}, f, indent=2)

    def update_model(
        self,
        model_id: str,
        sample_count: int,
        metrics: Dict[str, Any],
        status: str = "ACTIVE",
        version: Optional[str] = None
    ):
        if model_id in self._models:
            meta = self._models[model_id]
            meta.sample_count = sample_count
            meta.metrics.update(metrics)
            meta.status = status
            meta.trained_at = datetime.now().isoformat(timespec="seconds")
            if version:
                meta.version = version
            self.save()

    def get_model(self, model_id: str) -> Optional[ModelMetadata]:
        return self._models.get(model_id)

    def get_all(self) -> List[Dict[str, Any]]:
        results = []
        for m in self._models.values():
            artifact_full = BASE_DIR / m.artifact_path
            # Dynamically verify existence
            m_copy = m.model_dump()
            if not artifact_full.exists():
                m_copy["status"] = "UNTRAINED"
            else:
                m_copy["artifact_size_bytes"] = artifact_full.stat().st_size
            results.append(m_copy)
        return results

    def get_model_versions_signature(self) -> str:
        parts = [f"{m.model_id}:{m.version}" for m in sorted(self._models.values(), key=lambda x: x.model_id)]
        return ";".join(parts)


registry = ModelRegistry()
