"""
Trains the prompt classifier and saves it to ml/model.joblib

Model: TF-IDF (word + 2-word phrases) -> Logistic Regression
Run:  python ml/train_model.py
"""
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

BASE = Path(__file__).resolve().parent

df = pd.read_csv(BASE / "dataset.csv")
print("dataset size:", len(df))
print(df["label"].value_counts(), "\n")

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(lowercase=True, ngram_range=(1, 2), sublinear_tf=True)),
    ("clf", LogisticRegression(max_iter=1000, C=10)),
])

model.fit(X_train, y_train)

pred = model.predict(X_test)
print("test accuracy:", round(accuracy_score(y_test, pred), 3))
print(classification_report(y_test, pred, zero_division=0))

# train once more on everything before saving
model.fit(df["text"], df["label"])
joblib.dump(model, BASE / "model.joblib")
print("model saved to", BASE / "model.joblib")
