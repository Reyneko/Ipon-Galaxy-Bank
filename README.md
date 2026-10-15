# 🪐 Ipon Galaxy Bank — *"Saving pesos across the universe"*

A simulated online banking app for a school project. No real money involved.

**Stack:** Flask 3 · Flask-SQLAlchemy · PostgreSQL (psycopg2) · Gunicorn · Jinja2 · Tailwind CSS · Lucide icons · vanilla JS (Fetch API) · python-dotenv

## Features

**Admin** (login with username + password)
- Create customers → auto-generates a 10-digit account number and a random 4-digit **default PIN** (shown once)
- Reset PINs, lock / unlock accounts
- Dashboard stats and a live **audit log**

**Customer** (login with account number + PIN)
- Simulated **deposit** and **withdrawal**
- Check balance (with hide/show eye icon)
- **Change PIN** (forced on first login with the default PIN)
- Transaction history and recent security activity

**Security features**
- PIN re-entry required for *every* transaction
- **After every transaction:** PIN field is cleared, the form re-locks, CSRF token rotates, and a receipt appears with a unique reference number, timestamp and IP — plus a **"Not me — lock my account"** panic button
- 3 wrong PINs → account locks (admin must unlock)
- Hashed PINs/passwords (Werkzeug), CSRF protection, 5-minute idle auto-logout, daily withdrawal limit (₱50,000), secure headers
- Everything is saved to the database: users, transactions, and the audit log

## Run locally

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # then edit it
python app.py               # http://localhost:5000
```
Without `DATABASE_URL` it uses a local SQLite file, so you don't need PostgreSQL to try it.

## Deploy on Render (free)

1. Push this folder to a **GitHub** repo.
2. On [render.com](https://render.com): **New → Blueprint**, pick the repo. `render.yaml` creates the web service **and** a free PostgreSQL database and wires `DATABASE_URL` for you.
3. When asked, enter an `ADMIN_PASSWORD`.
4. Wait for the build, then open the `https://<your-service>.onrender.com` URL. Tables and the admin account are created automatically on first boot.

*Manual setup instead?* Create a PostgreSQL instance, then a Web Service with build `pip install -r requirements.txt`, start `gunicorn app:app`, and env vars `DATABASE_URL` (Internal Database URL), `SECRET_KEY`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`.

> Free Render services sleep after inactivity, so the first load may take ~50 seconds.

## Demo flow
1. Log in as admin → create a customer, copy the account number + default PIN.
2. Log out, log in as the customer → set a new PIN.
3. Deposit / withdraw, watch the receipt + security panel, check the history.
4. Try 3 wrong PINs to see the lockout, then unlock it as admin.
