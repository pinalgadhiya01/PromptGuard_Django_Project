# PromptGuard - AI Application Security Testing Platform

A Django web application that scans prompts and documents for attacks on AI
applications (prompt injection, jailbreak, system prompt extraction, sensitive
information extraction, role manipulation), gives a 0-100 risk score, explains
why the text was flagged and generates a PDF report.

## How to run (Windows / Linux / Mac)

1. Open a terminal inside this folder.
2. (optional) create a virtual environment:
       python -m venv venv
       venv\Scripts\activate          (Windows)
       source venv/bin/activate       (Linux / Mac)
3. Install the packages:
       pip install -r requirements.txt
4. Create the database tables:
       python manage.py migrate
5. Start the server:
       python manage.py runserver
6. Open http://127.0.0.1:8000/ in the browser.

A demo database is already included, so you can log in directly:
    username: demo      password: Demo@12345
    (admin panel at /admin/  ->  admin / Admin@12345)

To retrain the ML model:
    python ml/make_dataset.py
    python ml/train_model.py

To run the tests:
    python manage.py test

## Project structure

    promptguard/      project settings and main urls
    accounts/         register, login, logout, profile (Module 1)
    scanner/          models, views, forms, PDF report, dashboard (Modules 2, 6, 7, 8)
    scanner/engine/  rules.py (keyword patterns), classifier.py (ML),
                      scoring.py (risk score), explain.py (explanations),
                      documents.py (PDF/TXT scanner), analyzer.py (combines all)
    ml/               dataset + training script + saved model
    templates/        HTML pages
    static/css/       stylesheet

## Risk scoring policy (project-defined, not a universal standard)
    0-20 Low | 21-40 Medium | 41-70 High | 71-100 Critical
Score = 40% ML model risk + 60% rule/pattern severity.
