"""Layer 2: behavioural anomaly detector (Objective 5) and its SHAP explanations (Objective 6).

An Isolation Forest (Liu, Ting and Zhou, 2008) is trained on the features of benign training calls only. Its
anomaly score is the negated scikit-learn `score_samples` value, so higher means more unusual. The alert
threshold is set on the benign calls of the validation user tasks so that at most 5% of them raise an alert.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from .features import FEATURES

N_TREES = 200
TARGET_FAR = 0.05


def far_threshold(benign_scores, far: float = TARGET_FAR) -> float:
    """Smallest threshold such that at most `far` of the benign scores are strictly above it."""
    s = np.sort(np.asarray(benign_scores, dtype=float))[::-1]
    k = int(np.floor(far * len(s)))
    return float(s[k]) if len(s) else float('inf')


class AnomalyDetector:
    def __init__(self, seed: int = 0, features=None, n_estimators: int = N_TREES):
        self.seed = seed
        self.features = list(features or FEATURES)
        self.model = IsolationForest(n_estimators=n_estimators, max_samples='auto', contamination='auto',
                                     random_state=seed)
        self.threshold = None
        self.benign_median = None
        self._explainer = None

    def fit(self, X_train: pd.DataFrame):
        X = X_train[self.features]
        self.model.fit(X.values)
        self.benign_median = X.median()
        self._explainer = None
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        return -self.model.score_samples(X[self.features].values)

    def calibrate(self, X_val_benign: pd.DataFrame, far: float = TARGET_FAR) -> float:
        self.threshold = far_threshold(self.score(X_val_benign), far)
        return self.threshold

    def alert(self, X: pd.DataFrame) -> np.ndarray:
        return self.score(X) > self.threshold

    # ------------------------------------------------------------------ explanations
    def explainer(self):
        if self._explainer is None:
            import shap
            self._explainer = shap.TreeExplainer(self.model)
        return self._explainer

    def anomaly_contributions(self, X: pd.DataFrame) -> pd.DataFrame:
        """Per-feature contribution to the anomaly score (positive = pushes the call towards 'anomalous').

        SHAP's TreeExplainer explains the Isolation Forest's path-length output, where a shorter path means more
        anomalous; the sign is therefore flipped so that positive values raise the anomaly score."""
        sv = self.explainer().shap_values(X[self.features].values)
        return pd.DataFrame(-np.asarray(sv), index=X.index, columns=self.features)

    def top_features(self, x_row: pd.Series, k: int = 3):
        c = self.anomaly_contributions(x_row.to_frame().T).iloc[0]
        top = c.sort_values(ascending=False).head(k)
        return [{'feature': f, 'value': float(x_row[f]), 'contribution': round(float(v), 4)} for f, v in top.items()]
