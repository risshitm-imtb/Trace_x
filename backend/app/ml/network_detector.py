import joblib
import pandas as pd
from pathlib import Path
from sqlalchemy import text
from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parents[3]
MODEL_PATH = BASE_DIR / "models" / "network_anomaly_model.joblib"

NETWORK_FEATURE_COLUMNS = [
    "src_ip_freq",
    "dst_ip_freq",
    "asn_freq",
    "country_freq",
    "src_port_norm",
    "is_standard_bitcoin_port"
]


def build_network_features(db: Session) -> pd.DataFrame:
    """Extract network observation features from database."""
    query = text("""
        SELECT
            observation_id,
            timestamp,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            txid,
            geo_country,
            asn
        FROM network_observations
    """)
    df = pd.read_sql(query, db.bind)

    if df.empty:
        return pd.DataFrame(columns=["observation_id"] + NETWORK_FEATURE_COLUMNS)

    # Calculate frequencies
    src_freq = df["src_ip"].value_counts().to_dict()
    dst_freq = df["dst_ip"].value_counts().to_dict()
    asn_freq = df["asn"].value_counts().to_dict()
    country_freq = df["geo_country"].value_counts().to_dict()

    df["src_ip_freq"] = df["src_ip"].map(src_freq).fillna(1).astype(float)
    df["dst_ip_freq"] = df["dst_ip"].map(dst_freq).fillna(1).astype(float)
    df["asn_freq"] = df["asn"].map(asn_freq).fillna(1).astype(float)
    df["country_freq"] = df["geo_country"].map(country_freq).fillna(1).astype(float)
    df["src_port_norm"] = (pd.to_numeric(df["src_port"], errors="coerce").fillna(0) / 65535.0).clip(0, 1)
    df["is_standard_bitcoin_port"] = (df["dst_port"].astype(str) == "8333").astype(float)

    return df


class NetworkAnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=150,
            contamination=0.06,
            random_state=42,
            n_jobs=-1
        )

    def fit(self, features: pd.DataFrame):
        X = features[NETWORK_FEATURE_COLUMNS].copy()
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        return self

    def predict(self, features: pd.DataFrame) -> pd.DataFrame:
        X = features[NETWORK_FEATURE_COLUMNS].copy()
        X_scaled = self.scaler.transform(X)

        labels = self.model.predict(X_scaled)
        scores = self.model.decision_function(X_scaled)

        result = features.copy()
        result["net_anomaly_label"] = labels
        result["net_anomaly_score"] = -scores
        return result

    def save(self, path: str = str(MODEL_PATH)):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "scaler": self.scaler}, path)

    def load(self, path: str = str(MODEL_PATH)):
        artifact = joblib.load(path)
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        return self
