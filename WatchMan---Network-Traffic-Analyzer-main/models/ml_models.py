"""
models/ml_models.py — Machine Learning Models for IDRS.

Integrates Random Forest (multiclass traffic classification) and
Isolation Forest (unsupervised anomaly detection) on CPU.
If pre-trained models are not found on disk, generates high-quality synthetic
training data and trains lightweight, fast models on first initialization.
"""

import os
import pickle
import logging
import random
import numpy as np
from pathlib import Path

# Try importing scikit-learn
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

log = logging.getLogger("watchman.ml")

MODEL_DIR = Path(__file__).parent
RF_MODEL_PATH = MODEL_DIR / "random_forest.pkl"
IF_MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"

CLASSES = [
    "Normal",
    "DoS",
    "Port Scan",
    "SSH Brute Force",
    "DNS Attack",
    "Unknown Attack"
]

class IDRSModelManager:
    """
    Manages loading, predicting, and training of Random Forest & Isolation Forest models.
    Thread-safe and optimized for real-time CPU execution (< 5ms per inference).
    """
    def __init__(self):
        self.rf_classifier = None
        self.if_detector = None
        self.loaded = False
        self.initialize()

    def initialize(self):
        """Load models from disk or train synthetic models if missing/sklearn unavailable."""
        if not SKLEARN_AVAILABLE:
            log.warning("scikit-learn not installed. Using rule-backed heuristic fallbacks for ML inference.")
            self.loaded = False
            return

        try:
            if RF_MODEL_PATH.exists() and IF_MODEL_PATH.exists():
                with open(RF_MODEL_PATH, "rb") as f:
                    self.rf_classifier = pickle.load(f)
                with open(IF_MODEL_PATH, "rb") as f:
                    self.if_detector = pickle.load(f)
                log.info("Loaded pre-trained Random Forest and Isolation Forest models from %s", MODEL_DIR)
                self.loaded = True
            else:
                log.info("ML models not found in %s. Training lightweight synthetic models out-of-the-box...", MODEL_DIR)
                self._train_and_save_synthetic_models()
                self.loaded = True
        except Exception as e:
            log.error("Error initializing ML models (%s). Retraining synthetic models...", e)
            try:
                self._train_and_save_synthetic_models()
                self.loaded = True
            except Exception as e2:
                log.error("Failed to train synthetic models: %s. Using heuristic fallbacks.", e2)
                self.loaded = False

    def _train_and_save_synthetic_models(self):
        """Generate synthetic dataset matching our 8-feature vector and train models."""
        X_train = []
        y_train = []

        # Feature vector: [proto_code, sport, dport, size, flags_code, duration, bps, pps]
        # proto_map: TCP=1, UDP=2, ICMP=3, DNS=4, HTTP=5, HTTPS=6, SSH=7, ...
        # flags_map: NONE=0, S=1, SA=2, A=3, PA=4, FA=5, R=6, ...

        for _ in range(300):
            # Normal traffic (HTTP, HTTPS, DNS, TCP typical)
            proto = random.choice([1, 2, 4, 5, 6])
            sport = random.randint(30000, 65000)
            dport = random.choice([80, 443, 53, 8080])
            size = random.randint(64, 1460)
            flags = random.choice([3, 4])  # A or PA
            dur = random.uniform(0.1, 10.0)
            pps = random.uniform(1.0, 50.0)
            bps = pps * size
            X_train.append([proto, sport, dport, size, flags, dur, bps, pps])
            y_train.append("Normal")

        for _ in range(150):
            # DoS traffic (High pps, small packets, SYN flags or HTTP floods)
            proto = random.choice([1, 5])
            sport = random.randint(10000, 65000)
            dport = 80
            size = random.choice([64, 120])
            flags = 1  # SYN
            dur = random.uniform(0.01, 1.0)
            pps = random.uniform(300.0, 5000.0)
            bps = pps * size
            X_train.append([proto, sport, dport, size, flags, dur, bps, pps])
            y_train.append("DoS")

        for _ in range(150):
            # Port Scan (Many unique dports or rapid SYN checks, small size)
            proto = 1
            sport = random.randint(40000, 65000)
            dport = random.randint(1, 1000)
            size = 40
            flags = 1  # SYN
            dur = random.uniform(0.001, 0.5)
            pps = random.uniform(50.0, 500.0)
            bps = pps * size
            X_train.append([proto, sport, dport, size, flags, dur, bps, pps])
            y_train.append("Port Scan")

        for _ in range(150):
            # SSH Brute Force (Port 22, repeated small TCP auth attempts)
            proto = 7 if random.random() > 0.3 else 1
            sport = random.randint(40000, 65000)
            dport = 22
            size = random.randint(60, 200)
            flags = random.choice([1, 4])
            dur = random.uniform(0.05, 2.0)
            pps = random.uniform(10.0, 100.0)
            bps = pps * size
            X_train.append([proto, sport, dport, size, flags, dur, bps, pps])
            y_train.append("SSH Brute Force")

        for _ in range(100):
            # DNS Attack (Amplification / Flood on UDP port 53 with huge packet rates or large responses)
            proto = 4 if random.random() > 0.2 else 2
            sport = 53
            dport = random.randint(30000, 65000)
            size = random.randint(1200, 4096)
            flags = 0
            dur = random.uniform(0.01, 0.5)
            pps = random.uniform(200.0, 2000.0)
            bps = pps * size
            X_train.append([proto, sport, dport, size, flags, dur, bps, pps])
            y_train.append("DNS Attack")

        for _ in range(80):
            # Unknown Attack (Weird combos, malformed packets, unusual protocols/ports)
            proto = random.choice([3, 8, 9, 10, 11])
            sport = random.randint(1, 65000)
            dport = random.randint(1, 65000)
            size = random.randint(0, 9000)
            flags = random.choice([5, 6, 8])
            dur = random.uniform(0.001, 5.0)
            pps = random.uniform(100.0, 1000.0)
            bps = pps * size
            X_train.append([proto, sport, dport, size, flags, dur, bps, pps])
            y_train.append("Unknown Attack")

        X_train = np.array(X_train)
        y_train = np.array(y_train)

        # Train Random Forest Classifier
        self.rf_classifier = RandomForestClassifier(n_estimators=50, max_depth=12, random_state=42, n_jobs=1)
        self.rf_classifier.fit(X_train, y_train)

        # Train Isolation Forest on normal traffic + small mix for anomaly scoring
        self.if_detector = IsolationForest(n_estimators=50, contamination=0.15, random_state=42, n_jobs=1)
        self.if_detector.fit(X_train)

        # Save to disk
        try:
            with open(RF_MODEL_PATH, "wb") as f:
                pickle.dump(self.rf_classifier, f)
            with open(IF_MODEL_PATH, "wb") as f:
                pickle.dump(self.if_detector, f)
            log.info("Saved newly trained ML models to %s", MODEL_DIR)
        except Exception as e:
            log.warning("Could not save ML models to disk (%s). Models retained in memory.", e)

    def predict_traffic(self, feature_vector: list[float]) -> tuple[str, float]:
        """
        Classify traffic into one of the 6 classes using Random Forest.

        Returns:
            Tuple of (prediction_label, confidence_percentage [0.0 - 100.0])
        """
        if not self.loaded or not self.rf_classifier:
            return self._heuristic_classify(feature_vector)

        try:
            X = np.array(feature_vector).reshape(1, -1)
            probs = self.rf_classifier.predict_proba(X)[0]
            max_idx = np.argmax(probs)
            label = self.rf_classifier.classes_[max_idx]
            confidence = round(float(probs[max_idx]) * 100.0, 1)
            return label, confidence
        except Exception as e:
            log.debug("Prediction error: %s", e)
            return self._heuristic_classify(feature_vector)

    def anomaly_score(self, feature_vector: list[float]) -> float:
        """
        Compute anomaly score between 0.0 (totally normal) and 100.0 (extreme anomaly)
        using Isolation Forest decision function.
        """
        if not self.loaded or not self.if_detector:
            return self._heuristic_anomaly(feature_vector)

        try:
            X = np.array(feature_vector).reshape(1, -1)
            # decision_function returns negative values for outliers, positive for inliers
            # Typically range is roughly -0.5 to +0.5.
            df = float(self.if_detector.decision_function(X)[0])
            # Map df from [+0.3, -0.4] -> [0.0, 100.0] where lower df means higher anomaly
            score = (0.3 - df) / 0.7 * 100.0
            score = max(0.0, min(100.0, score))
            return round(score, 1)
        except Exception as e:
            log.debug("Anomaly score error: %s", e)
            return self._heuristic_anomaly(feature_vector)

    def _heuristic_classify(self, v: list[float]) -> tuple[str, float]:
        """Fallback rule-based heuristic when scikit-learn or model loading fails."""
        # v = [proto_code, sport, dport, size, flags_code, duration, bps, pps]
        proto, sport, dport, size, flags, dur, bps, pps = v
        if pps > 250 or (flags == 1 and pps > 50):
            return "DoS", 88.5
        elif dport == 22 and (size < 250 or pps > 10):
            return "SSH Brute Force", 84.0
        elif pps > 30 and size < 60 and dur < 0.5:
            return "Port Scan", 86.0
        elif (proto == 4 or sport == 53) and size > 1000:
            return "DNS Attack", 82.0
        elif proto not in [1, 2, 3, 4, 5, 6]:
            return "Unknown Attack", 75.0
        return "Normal", 95.0

    def _heuristic_anomaly(self, v: list[float]) -> float:
        """Fallback anomaly score calculation."""
        proto, sport, dport, size, flags, dur, bps, pps = v
        score = 10.0
        if pps > 200: score += 45.0
        if size > 3000: score += 20.0
        if proto > 7: score += 25.0
        return min(100.0, score)

# Global singleton instance
ml_manager = IDRSModelManager()
