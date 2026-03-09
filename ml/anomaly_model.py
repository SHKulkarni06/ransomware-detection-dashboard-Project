import numpy as np
from sklearn.ensemble import IsolationForest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.security_event import SecurityEvent

model = None
trained = False


def train_model(summaries):

    global model, trained

    if len(summaries) < 20:
        return

    X = []

    for s in summaries:

        X.append([
            s["packet_count"],
            s["avg_packet_size"],
            s["packet_rate"],
            len(s["protocols"])
        ])

    X = np.array(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.03,
        random_state=42
    )

    model.fit(X)

    trained = True


def detect_anomaly(summary):

    if not trained:
        return False

    X = np.array([[
        summary["packet_count"],
        summary["avg_packet_size"],
        summary["packet_rate"],
        len(summary["protocols"])
    ]])

    prediction = model.predict(X)

    return prediction[0] == -1