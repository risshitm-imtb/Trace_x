import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sqlalchemy import text
from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parents[3]
MODEL_PATH = BASE_DIR / "models" / "transaction_anomaly_model.joblib"

TRANSACTION_FEATURE_COLUMNS = [
    "total_input",
    "total_output",
    "fee",
    "fee_ratio",
    "input_count",
    "output_count",
    "fanout_ratio",
    "value_per_output",
]


def build_transaction_features(db: Session) -> pd.DataFrame:
    """Extract transaction-level forensic features from database."""
    query = text("""
        SELECT
            t.txid,
            t.fee,
            t.script_type,
            COALESCE((SELECT COUNT(*) FROM transaction_inputs ti WHERE ti.txid = t.txid), 0) AS input_count,
            COALESCE((SELECT COUNT(*) FROM transaction_outputs too WHERE too.txid = t.txid), 0) AS output_count,
            COALESCE((SELECT SUM(amount) FROM transaction_inputs ti WHERE ti.txid = t.txid), 0) AS total_input,
            COALESCE((SELECT SUM(amount) FROM transaction_outputs too WHERE too.txid = t.txid), 0) AS total_output
        FROM transactions t
    """)
    df = pd.read_sql(query, db.bind)

    if df.empty:
        return pd.DataFrame(columns=["txid"] + TRANSACTION_FEATURE_COLUMNS)

    for col in ["fee", "input_count", "output_count", "total_input", "total_output"]:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Derived forensic ratios
    df["fee_ratio"] = df["fee"] / (df["total_output"] + 1e-8)
    df["fanout_ratio"] = df["output_count"] / (df["input_count"].replace(0, 1))
    df["value_per_output"] = df["total_output"] / (df["output_count"].replace(0, 1))

    return df


class TransactionAnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        )

    def fit(self, features: pd.DataFrame):
        X = features[TRANSACTION_FEATURE_COLUMNS].copy()
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        return self

    def predict(self, features: pd.DataFrame) -> pd.DataFrame:
        X = features[TRANSACTION_FEATURE_COLUMNS].copy()
        X_scaled = self.scaler.transform(X)

        labels = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)

        result = features.copy()
        result["tx_anomaly_label"] = labels
        result["tx_anomaly_score"] = -scores
        return result

    def save(self, path: str = str(MODEL_PATH)):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler}, path)

    def load(self, path: str = str(MODEL_PATH)):
        artifact = joblib.load(path)
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        return self
