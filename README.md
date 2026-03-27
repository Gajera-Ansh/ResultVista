# ResultVista

## Overview
ResultVista is a comprehensive solution designed to streamline the process of result for educational institutions. This project focuses on providing users with easy access to results, analytics functionalities.

## Features
- **User-Friendly Interface:** An intuitive interface for easy navigation.
- **Calculate Result:** User upload the excel file with our requirement than user get a result table which have **total, percentage, grade, status**
- **Analytics Dashboard:** Visual representation of data to help analyze performance trends.
- **Download file:** User can download the result table in form of **excel file**, and also user can download the **chart PDF**.
- **Mail Integration:** When user create new account or delete account, user will get a confirmatioin mail.
- **Individual Student:** User can see any student result individually by clicking on row and if user want to share result to that student than enter email id of that student and the result PDF will be sent.

## Local Setup Instructions

### Option A – Docker Compose (recommended, no XAMPP needed)

Docker Compose starts both the Flask app and a MySQL 8.0 database with one command.

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Gajera-Ansh/ResultVista.git
   cd ResultVista
   ```

2. **Configure secrets (email & Google OAuth):**
   Create a `.env` file from the example template:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and fill in `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`, `CLIENT_ID`, and `CLIENT_SECRET`. The `DATABASE_URL` is set automatically by Docker Compose.

3. **Start the app + database:**
   ```bash
   docker compose up --build
   ```
   The app will be available at **http://localhost:5000**.  
   MySQL will be available at **localhost:3306** (database name: `user`, no password).

4. **Stop everything:**
   ```bash
   docker compose down
   ```
   Add `-v` to also delete the database volume (`docker compose down -v`).

---

### Option B – Manual (XAMPP)

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Gajera-Ansh/ResultVista.git
   cd ResultVista
   ```

2. **Install Libraries:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configuration:**
   Copy `.env.example` to `.env` and fill in all values.  
   Set `SESSION_COOKIE_SECURE=false` in `.env` when running locally over plain HTTP.

4. **Database setup:**
   Open XAMPP, start MySQL, and create a database named **user**.

5. **Run the project:**
   ```bash
   python app.py
   ```
   Then open **http://localhost:5000** in your browser.

## Deployment

### Deploy to Render.com (recommended)
`render.yaml` provisions **two services automatically**: the Flask web app and a MySQL database container with a persistent 5 GB disk.

1. Push your code to GitHub.
2. Go to [render.com](https://render.com) → **New** → **Blueprint** → connect your repository.
3. Render detects `render.yaml` and creates both services.
4. Set the following environment variables in the Render dashboard for the **web** service:
   - `MAIL_USERNAME` – Your Gmail address
   - `MAIL_PASSWORD` – Your Gmail [App Password](https://myaccount.google.com/apppasswords) (requires [2-Step Verification](https://myaccount.google.com/signinoptions/twosv) to be enabled)
   - `MAIL_DEFAULT_SENDER` – Your Gmail address
   - `CLIENT_ID` – Google OAuth Client ID
   - `CLIENT_SECRET` – Google OAuth Client Secret
   > `DATABASE_URL`, `SECRET_KEY`, `SESSION_FILE_DIR`, and `SESSION_COOKIE_SECURE` are configured automatically by `render.yaml`.
5. Click **Apply** — both services will deploy and the database will be connected automatically.

### Deploy to Railway
Railway auto-provisions MySQL and injects `DATABASE_URL` into the app.

1. Push your code to GitHub.
2. Go to [railway.app](https://railway.app) → **New Project** → **Deploy from GitHub repo**.
3. Add a **MySQL** database plugin — Railway sets `DATABASE_URL` automatically.
4. Add the remaining environment variables:
   - `SECRET_KEY`, `MAIL_USERNAME`, `MAIL_DEFAULT_SENDER`
   - `MAIL_PASSWORD` – Gmail [App Password](https://myaccount.google.com/apppasswords) (requires [2-Step Verification](https://myaccount.google.com/signinoptions/twosv))
   - `CLIENT_ID`, `CLIENT_SECRET`
   - `SESSION_FILE_DIR` → `/tmp/flask_session`
   - `SESSION_COOKIE_SECURE` → `true`
5. Railway uses the `Procfile` to start the app with gunicorn.

### Google OAuth – Authorized Redirect URI
After deploying, update your Google Cloud Console OAuth 2.0 credentials to allow:
```
https://<your-app-domain>/auth/callback
```

## Usage Guidelines
- **Logging In:** Use your credentials to log into the application. 
- **Upload excel file:** Upload excel file which in **example/Student_Marksheet_50_Students.xlsx** than click on **upload and validate** button
- **Generating Result:** after clicking on **upload and validate** button scroll down and click on **Process Results**

**To see screenshots open /screenshots/ folder**
