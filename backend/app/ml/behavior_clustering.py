import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.cluster import MiniBatchKMeans
from sklearn.preprocessing import StandardScaler

BASE_DIR = Path(__file__).resolve().parents[3]
MODEL_PATH = BASE_DIR / "models" / "behavior_clustering_model.joblib"

CLUSTER_FEATURE_COLUMNS = [
    "transaction_count",
    "tx_per_ip",
    "network_diversity",
    "flow_imbalance",
    "total_received",
]

ARCHETYPE_NAMES = {
    0: "Standard Retail / P2P",
    1: "High Velocity Relay",
    2: "Peeling Chain Layer",
    3: "Mixing / Tumbler Pool",
    4: "Consolidator / Cold Vault",
}


class BehaviorClusterModel:
    def __init__(self, n_clusters: int = 5):
        self.n_clusters = n_clusters
        self.scaler = StandardScaler()
        self.model = MiniBatchKMeans(
            n_clusters=n_clusters,
            random_state=42,
            batch_size=256
        )
        self.cluster_profiles_ = {}

    def fit(self, features: pd.DataFrame):
        X = features[CLUSTER_FEATURE_COLUMNS].copy()
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

        # Profile each cluster's distribution
        labels = self.model.predict(X_scaled)
        features_copy = X.copy()
        features_copy["cluster"] = labels

        self.cluster_profiles_ = {}
        for c in range(self.n_clusters):
            c_data = features_copy[features_copy["cluster"] == c]
            if len(c_data) > 0:
                self.cluster_profiles_[c] = {
                    "count": int(len(c_data)),
                    "name": ARCHETYPE_NAMES.get(c, f"Archetype {c}"),
                    "mean": c_data[CLUSTER_FEATURE_COLUMNS].mean().to_dict(),
                    "std": c_data[CLUSTER_FEATURE_COLUMNS].std().fillna(0.1).to_dict(),
                    "min": c_data[CLUSTER_FEATURE_COLUMNS].min().to_dict(),
                    "max": c_data[CLUSTER_FEATURE_COLUMNS].max().to_dict(),
                }
            else:
                self.cluster_profiles_[c] = {
                    "count": 0,
                    "name": ARCHETYPE_NAMES.get(c, f"Archetype {c}"),
                    "mean": {col: 1.0 for col in CLUSTER_FEATURE_COLUMNS},
                    "std": {col: 0.5 for col in CLUSTER_FEATURE_COLUMNS},
                    "min": {col: 0.0 for col in CLUSTER_FEATURE_COLUMNS},
                    "max": {col: 10.0 for col in CLUSTER_FEATURE_COLUMNS},
                }

        return self

    def predict(self, features: pd.DataFrame) -> pd.DataFrame:
        X = features[CLUSTER_FEATURE_COLUMNS].copy()
        X_scaled = self.scaler.transform(X)
        labels = self.model.predict(X_scaled)

        result = features.copy()
        result["cluster_id"] = labels
        result["cluster_name"] = [ARCHETYPE_NAMES.get(l, f"Cluster {l}") for l in labels]
        return result

    def get_cluster_profiles(self):
        return self.cluster_profiles_

    def save(self, path: str = str(MODEL_PATH)):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "cluster_profiles": self.cluster_profiles_,
                "n_clusters": self.n_clusters
            },
            path
        )

    def load(self, path: str = str(MODEL_PATH)):
        artifact = joblib.load(path)
        self.model = artifact["model"]
        self.scaler = artifact["scaler"]
        self.cluster_profiles_ = artifact.get("cluster_profiles", {})
        self.n_clusters = artifact.get("n_clusters", 5)
        return self
