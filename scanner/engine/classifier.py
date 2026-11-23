"""
Loads the trained scikit-learn model and predicts the category of a text.
If the model file is missing it trains one automatically (so the project still runs).
"""
from pathlib import Path

import joblib

ML_DIR = Path(__file__).resolve().parent.parent.parent / "ml"
MODEL_PATH = ML_DIR / "model.joblib"

_model = None  # cached after first load


def _train_if_needed():
    # fallback - should not normally happen if model.joblib is shipped with the project
    import subprocess
    import sys
    subprocess.run([sys.executable, str(ML_DIR / "make_dataset.py")], check=True)
    subprocess.run([sys.executable, str(ML_DIR / "train_model.py")], check=True)


def get_model():
    global _model
    if _model is None:
        if not MODEL_PATH.exists():
            _train_if_needed()
        _model = joblib.load(MODEL_PATH)
    return _model


def predict(text):
    """
    Returns (label, confidence, probabilities_dict)
    confidence = probability of the predicted label (0 to 1)
    """
    model = get_model()
    probs = model.predict_proba([text])[0]
    classes = list(model.classes_)
    best = max(range(len(classes)), key=lambda i: probs[i])
    prob_dict = {classes[i]: float(probs[i]) for i in range(len(classes))}
    return classes[best], float(probs[best]), prob_dict
