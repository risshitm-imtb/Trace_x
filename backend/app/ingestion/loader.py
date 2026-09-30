import json
from datetime import datetime
from decimal import Decimal

import pandas as pd
from sqlalchemy.orm import Session

from backend.app.models import (
    IPAddress,
    NetworkObservation,
    Transaction,
    TransactionInput,
    TransactionOutput,
    Wallet,
)


REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "txid",
    "input_addresses",
    "output_addresses",
    "input_amounts",
    "output_amounts",
    "geo_country",
    "asn",
    "fee",
    "script_type",
]


def parse_json_array(value):
    if pd.isna(value):
        return []

    if isinstance(value, list):
        return value

    return json.loads(value)


def parse_timestamp(value):
    return datetime.fromisoformat(str(value))


def validate_columns(df):
    missing = [
        column
        for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )


def get_or_create_wallet(
    db: Session,
    address: str,
    timestamp: datetime,
):
    wallet = db.get(Wallet, address)

    if wallet is None:
        wallet = Wallet(
            address=address,
            first_seen=timestamp,
            last_seen=timestamp,
            transaction_count=0,
            total_received=0,
            total_sent=0,
        )

        db.add(wallet)
        db.flush()

    else:
        if (
            wallet.first_seen is None
            or timestamp < wallet.first_seen
        ):
            wallet.first_seen = timestamp

        if (
            wallet.last_seen is None
            or timestamp > wallet.last_seen
        ):
            wallet.last_seen = timestamp

    return wallet


def get_or_create_ip(
    db: Session,
    address: str,
    country: str,
    asn: str,
    timestamp: datetime,
):
    ip = db.get(IPAddress, address)

    if ip is None:
        ip = IPAddress(
            address=address,
            country=country,
            asn=asn,
            first_seen=timestamp,
            last_seen=timestamp,
            observation_count=0,
        )

        db.add(ip)
        db.flush()

    else:
        if (
            ip.first_seen is None
            or timestamp < ip.first_seen
        ):
            ip.first_seen = timestamp

        if (
            ip.last_seen is None
            or timestamp > ip.last_seen
        ):
            ip.last_seen = timestamp

    return ip


def load_csv_to_database(
    csv_path: str,
    db: Session,
):

    print("Loading dataset...")

    df = pd.read_csv(csv_path)

    print(f"Rows detected: {len(df)}")

    validate_columns(df)

    transactions_added = 0
    inputs_added = 0
    outputs_added = 0
    observations_added = 0

    wallet_addresses = set()
    ip_addresses = set()

    try:

        for index, row in df.iterrows():

            txid = str(row["txid"])
            timestamp = parse_timestamp(
                row["timestamp"]
            )

            # =================================================
            # TRANSACTION
            # =================================================

            transaction = db.get(
                Transaction,
                txid
            )

            if transaction is None:

                transaction = Transaction(
                    txid=txid,
                    timestamp=timestamp,
                    fee=Decimal(
                        str(row["fee"])
                    ),
                    script_type=str(
                        row["script_type"]
                    ),
                )

                db.add(transaction)

                transactions_added += 1

            # =================================================
            # INPUTS
            # =================================================

            input_addresses = parse_json_array(
                row["input_addresses"]
            )

            input_amounts = parse_json_array(
                row["input_amounts"]
            )

            for address, amount in zip(
                input_addresses,
                input_amounts
            ):

                address = str(address)
                amount = Decimal(str(amount))

                wallet = get_or_create_wallet(
                    db,
                    address,
                    timestamp,
                )

                wallet_addresses.add(address)

                wallet.total_sent = (
                    wallet.total_sent
                    + amount
                )

                wallet.transaction_count = (
                    wallet.transaction_count
                    + 1
                )

                db.add(
                    TransactionInput(
                        txid=txid,
                        wallet_address=address,
                        amount=amount,
                    )
                )

                inputs_added += 1

            # =================================================
            # OUTPUTS
            # =================================================

            output_addresses = parse_json_array(
                row["output_addresses"]
            )

            output_amounts = parse_json_array(
                row["output_amounts"]
            )

            for address, amount in zip(
                output_addresses,
                output_amounts
            ):

                address = str(address)
                amount = Decimal(str(amount))

                wallet = get_or_create_wallet(
                    db,
                    address,
                    timestamp,
                )

                wallet_addresses.add(address)

                wallet.total_received = (
                    wallet.total_received
                    + amount
                )

                db.add(
                    TransactionOutput(
                        txid=txid,
                        wallet_address=address,
                        amount=amount,
                    )
                )

                outputs_added += 1

            # =================================================
            # NETWORK OBSERVATION
            # =================================================

            src_ip = str(row["src_ip"])
            dst_ip = str(row["dst_ip"])

            country = str(
                row["geo_country"]
            )

            asn = str(row["asn"])

            # Source IP
            source_ip = get_or_create_ip(
                db,
                src_ip,
                country,
                asn,
                timestamp,
            )

            source_ip.observation_count += 1
            ip_addresses.add(src_ip)

            # Destination IP
            destination_ip = get_or_create_ip(
                db,
                dst_ip,
                country,
                asn,
                timestamp,
            )

            destination_ip.observation_count += 1
            ip_addresses.add(dst_ip)

            # Observation
            db.add(
                NetworkObservation(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(
                        row["src_port"]
                    ),
                    dst_port=int(
                        row["dst_port"]
                    ),
                    txid=txid,
                    geo_country=country,
                    asn=asn,
                )
            )

            observations_added += 1

            # -------------------------------------------------
            # Periodic commit
            # -------------------------------------------------

            if observations_added % 250 == 0:

                db.commit()

                print(
                    f"Processed "
                    f"{observations_added}/"
                    f"{len(df)} rows..."
                )

        db.commit()

    except Exception:

        db.rollback()

        raise

    print()
    print("========================================")
    print("TRACE-X INGESTION COMPLETE")
    print("========================================")
    print(
        f"Transactions : {transactions_added}"
    )
    print(
        f"Inputs       : {inputs_added}"
    )
    print(
        f"Outputs      : {outputs_added}"
    )
    print(
        f"Observations : {observations_added}"
    )
    print("========================================")

    return {
        "transactions": transactions_added,
        "inputs": inputs_added,
        "outputs": outputs_added,
        "observations": observations_added,
        "wallets": len(wallet_addresses),
        "ips": len(ip_addresses),
    }