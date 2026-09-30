from pathlib import Path
import pandas as pd
from backend.app.core.database import SessionLocal
from backend.app.ml.features import (
    build_wallet_features,
    get_ml_features,
)
from backend.app.ml.detector import WalletAnomalyDetector
from backend.app.ml.risk import (
    calculate_risk_scores,
    generate_explanation,
)

BASE_DIR = Path(__file__).resolve().parents[3]
MODEL_PATH = BASE_DIR / "models" / "wallet_anomaly_model.joblib"

_detection_cache = None


def run_detection(force_refresh: bool = False):
    global _detection_cache
    if _detection_cache is not None and not force_refresh:
        return _detection_cache

    db = SessionLocal()

    try:
        wallet_df = build_wallet_features(db)

        if wallet_df is None or wallet_df.empty:
            return pd.DataFrame()

        features = get_ml_features(wallet_df)

        detector = WalletAnomalyDetector()
        if MODEL_PATH.exists():
            detector.load(str(MODEL_PATH))
            results = detector.predict(features)
        else:
            detector.fit(features)
            results = detector.predict(features)
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            detector.save(str(MODEL_PATH))

        results["wallet_address"] = wallet_df[
            "wallet_address"
        ].values

        results = calculate_risk_scores(results)

        results["explanation"] = results.apply(
            generate_explanation,
            axis=1
        )

        results = results.sort_values(
            "risk_score",
            ascending=False
        )

        _detection_cache = results
        return results

    finally:
        db.close()


def clear_detection_cache():
    global _detection_cache
    _detection_cache = None

