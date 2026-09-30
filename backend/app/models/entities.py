from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
)

from backend.app.core.database import Base


class Wallet(Base):
    __tablename__ = "wallets"

    address = Column(String(128), primary_key=True)

    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    transaction_count = Column(Integer, default=0)
    total_received = Column(Numeric(24, 8), default=0)
    total_sent = Column(Numeric(24, 8), default=0)


class IPAddress(Base):
    __tablename__ = "ip_addresses"

    address = Column(String(45), primary_key=True)

    country = Column(String(100), nullable=True)
    asn = Column(String(50), nullable=True)

    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    observation_count = Column(Integer, default=0)


class Transaction(Base):
    __tablename__ = "transactions"

    txid = Column(String(128), primary_key=True)

    timestamp = Column(DateTime, nullable=False)

    fee = Column(Numeric(24, 8), nullable=True)
    script_type = Column(String(100), nullable=True)


class TransactionInput(Base):
    __tablename__ = "transaction_inputs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    txid = Column(
        String(128),
        ForeignKey("transactions.txid"),
        nullable=False
    )

    wallet_address = Column(
        String(128),
        ForeignKey("wallets.address"),
        nullable=False
    )

    amount = Column(Numeric(24, 8), nullable=False)

    __table_args__ = (
        Index("idx_input_txid", "txid"),
        Index("idx_input_wallet", "wallet_address"),
    )


class TransactionOutput(Base):
    __tablename__ = "transaction_outputs"

    id = Column(Integer, primary_key=True, autoincrement=True)

    txid = Column(
        String(128),
        ForeignKey("transactions.txid"),
        nullable=False
    )

    wallet_address = Column(
        String(128),
        ForeignKey("wallets.address"),
        nullable=False
    )

    amount = Column(Numeric(24, 8), nullable=False)

    __table_args__ = (
        Index("idx_output_txid", "txid"),
        Index("idx_output_wallet", "wallet_address"),
    )


class NetworkObservation(Base):
    __tablename__ = "network_observations"

    observation_id = Column(Integer, primary_key=True, autoincrement=True)

    timestamp = Column(DateTime, nullable=False)

    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45), nullable=False)

    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)

    txid = Column(
        String(128),
        ForeignKey("transactions.txid"),
        nullable=True
    )

    geo_country = Column(String(100), nullable=True)
    asn = Column(String(50), nullable=True)

    __table_args__ = (
        Index("idx_observation_timestamp", "timestamp"),
        Index("idx_observation_src_ip", "src_ip"),
        Index("idx_observation_dst_ip", "dst_ip"),
        Index("idx_observation_txid", "txid"),
    )


class AnalysisSession(Base):
    __tablename__ = "analysis_sessions"

    id = Column(String(64), primary_key=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(32), default="COMPLETED")
    dataset_name = Column(String(255), nullable=True)
    total_transactions = Column(Integer, default=0)
    total_wallets = Column(Integer, default=0)
    high_risk_alerts = Column(Integer, default=0)
    anomalies_detected = Column(Integer, default=0)
    max_risk = Column(Numeric(5, 2), default=0)
    average_risk = Column(Numeric(5, 2), default=0)


class GeneratedDataset(Base):
    __tablename__ = "generated_datasets"

    id = Column(String(64), primary_key=True)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    generated_at = Column(DateTime, nullable=False)
    seed = Column(Integer, nullable=False)
    row_count = Column(Integer, default=3000)
    fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    model_signature = Column(String(255), nullable=False)
    model_versions = Column(Text, nullable=True)
    scenario_distribution = Column(Text, nullable=True)
    behavior_mix = Column(String(255), nullable=True)
    parameters = Column(Text, nullable=True)
    validation_status = Column(String(32), default="VALIDATED")
    analysis_status = Column(String(32), default="READY")
    transaction_count = Column(Integer, default=0)
    wallet_count = Column(Integer, default=0)
    high_risk_count = Column(Integer, default=0)
    max_risk = Column(Numeric(5, 2), default=0)
    average_risk = Column(Numeric(5, 2), default=0)
    anomalies_detected = Column(Integer, default=0)