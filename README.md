# ResultVista

## Overview
ResultVista is a comprehensive solution designed to streamline the process of result management for educational institutions. This project focuses on providing users with easy access to results and analytics functionalities.

## Features
- **User-Friendly Interface:** An intuitive interface for easy navigation.
- **Calculate Result:** Upload an Excel file and get a result table with **total, percentage, grade, and status**.
- **Analytics Dashboard:** Visual representation of data to help analyze performance trends.
- **Download File:** Download the result table as an **Excel file** or download the **chart as a PDF**.
- **Mail Integration:** Confirmation emails are sent when a user creates or deletes an account.
- **Individual Student:** View any student's result individually, and send the result PDF to the student by email.

---

## 🖥️ Part 1 — Run the App Locally (on Your Computer)

### Step 1 — Install the required software

Install these three programs on your computer (all free):

| Program | What it's for | Download link |
|---------|--------------|---------------|
| **Python 3.11+** | Runs the Flask app | https://www.python.org/downloads/ |
| **PostgreSQL 14+** | The database | https://www.postgresql.org/download/ |
| **pgAdmin 4** | Visual GUI to see your database (comes bundled with PostgreSQL installer) | https://www.pgadmin.org/download/ |

> **Tip:** When installing PostgreSQL, the installer will ask you to set a **password for the `postgres` user**. Write it down — you will need it.

---

### Step 2 — Create the database in pgAdmin

1. Open **pgAdmin 4** (search for it in your Start menu / Applications).
2. In the left panel, expand **Servers → PostgreSQL → Databases**.
3. Right-click **Databases** → **Create** → **Database…**
4. In the **Database** field type: `resultvista`
5. Click **Save**.

You should now see `resultvista` listed under Databases. ✅

---

### Step 3 — Download the project code

Open a terminal (Command Prompt on Windows, Terminal on Mac/Linux) and run:

```bash
git clone https://github.com/Gajera-Ansh/ResultVista.git
cd ResultVista
```

---

### Step 4 — Install Python packages

```bash
pip install -r requirements.txt
```

This installs Flask, SQLAlchemy, and all other libraries the app needs.

---

### Step 5 — Create your `.env` file

Copy the example file:

```bash
# On Windows:
copy .env.example .env

# On Mac / Linux:
cp .env.example .env
```

Now open `.env` in any text editor (Notepad, VS Code, etc.) and fill in your values:

```
# Replace <your_postgres_password> with the password you set during PostgreSQL install
DATABASE_URL=postgresql://postgres:<your_postgres_password>@localhost:5432/resultvista

# Your Gmail address and App Password (see Step 6 below)
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password_here
MAIL_DEFAULT_SENDER=your_email@gmail.com

# A random secret string (type anything long and random)
SECRET_KEY=some-very-long-random-string-here

# Google OAuth (see Step 7 below)
CLIENT_ID=your_google_client_id_here
CLIENT_SECRET=your_google_client_secret_here

# Run over plain HTTP locally, so set this to false
SESSION_COOKIE_SECURE=false
```

---

### Step 6 — Set up Gmail App Password (for email features)

> Skip this step if you don't want email features yet — the app will still run.

1. Go to your Google Account → **Security** → enable **2-Step Verification**.
2. Then go to **Security** → **App Passwords**.
3. Select app: **Mail**, device: **Other (custom name)** → type `ResultVista` → click **Generate**.
4. Copy the 16-character password and paste it as `MAIL_PASSWORD` in your `.env` file.

---

### Step 7 — Set up Google OAuth (for "Sign in with Google")

> Skip this step if you don't need Google login yet.

1. Go to https://console.cloud.google.com/
2. Create a new project → go to **APIs & Services** → **OAuth consent screen** → fill in your app name.
3. Go to **APIs & Services** → **Credentials** → **Create Credentials** → **OAuth client ID**.
4. Application type: **Web application**.
5. Under **Authorized redirect URIs** add: `http://localhost:5000/auth/callback`
6. Click **Create** — copy the **Client ID** and **Client Secret** into your `.env` file.

---

### Step 8 — Run the app

```bash
python app.py
```

Open your browser and go to: **http://localhost:5000**

The app will automatically create all the database tables on first run. ✅

---

### Step 9 — View your data in pgAdmin

1. Open **pgAdmin 4**.
2. In the left panel: **Servers → PostgreSQL → Databases → resultvista → Schemas → public → Tables**.
3. Right-click the **users** table → **View/Edit Data → All Rows**.
4. You will see all registered users in a spreadsheet-like view! 🎉

---

## 🚀 Part 2 — Deploy to the Internet (Railway — Free Tier)

Railway is a cloud platform that hosts your app and provides a free PostgreSQL database. No credit card needed for basic usage.

### Step 1 — Push your code to GitHub

If you haven't already, push the project to your own GitHub account:

```bash
git remote set-url origin https://github.com/<your-username>/ResultVista.git
git push -u origin main
```

---

### Step 2 — Sign up on Railway

1. Go to https://railway.app
2. Click **Login** → **Login with GitHub** → authorize Railway.

---

### Step 3 — Create a new project

1. Click **New Project**.
2. Choose **Deploy from GitHub repo**.
3. Select your `ResultVista` repository.
4. Railway will detect it as a Python project. In your Railway web service settings, set the **Start Command** to:
   ```
   gunicorn --workers 4 --bind 0.0.0.0:$PORT app:app
   ```

---

### Step 4 — Add a PostgreSQL database

1. In your Railway project dashboard, click **+ New** (top right).
2. Choose **Database** → **Add PostgreSQL**.
3. Railway creates a PostgreSQL database and automatically adds a `DATABASE_URL` variable to your project. ✅

---

### Step 5 — Add the remaining environment variables

1. Click on your **web service** (the Flask app tile).
2. Go to the **Variables** tab.
3. Add each variable:

| Variable | Value |
|----------|-------|
| `MAIL_USERNAME` | your Gmail address |
| `MAIL_PASSWORD` | your Gmail App Password |
| `MAIL_DEFAULT_SENDER` | your Gmail address |
| `CLIENT_ID` | your Google OAuth Client ID |
| `CLIENT_SECRET` | your Google OAuth Client Secret |
| `SESSION_FILE_DIR` | `/tmp/flask_session` |
| `SESSION_COOKIE_SECURE` | `true` |

> `DATABASE_URL` and `SECRET_KEY` are already set automatically.

---

### Step 6 — Update Google OAuth redirect URI

1. Go back to https://console.cloud.google.com → your project → **APIs & Services → Credentials**.
2. Edit your OAuth Client ID.
3. Under **Authorized redirect URIs**, add your Railway URL:
   ```
   https://<your-app>.railway.app/auth/callback
   ```
4. Click **Save**.

---

### Step 7 — View your live database with pgAdmin

You can connect pgAdmin on your local computer to the Railway PostgreSQL database:

1. In Railway dashboard, click on the **PostgreSQL** tile.
2. Go to the **Variables** tab and note these values:
   - `PGHOST` (the host)
   - `PGPORT` (usually `5432`)
   - `PGDATABASE` (the database name)
   - `PGUSER` (the username)
   - `PGPASSWORD` (the password)

3. Open **pgAdmin 4** on your computer.
4. Right-click **Servers** → **Register** → **Server…**
5. Fill in the details:
   - **Name:** `ResultVista Railway` (any name you like)
   - **Connection** tab:
     - **Host:** paste the `PGHOST` value
     - **Port:** paste the `PGPORT` value
     - **Database:** paste the `PGDATABASE` value
     - **Username:** paste the `PGUSER` value
     - **Password:** paste the `PGPASSWORD` value
6. Click **Save**.

You can now browse your live production database from pgAdmin! 🎉

---

## ☁️ Part 3 — Deploy to Render.com (alternative)

Render.com is another free hosting platform. It uses the `render.yaml` file already included in the project.

### Step 1 — Get a free PostgreSQL database
Create a free PostgreSQL database on [Railway](https://railway.app) (PostgreSQL plugin only, no app deployment needed), [Supabase](https://supabase.com), or any managed PostgreSQL provider. Copy the connection string — it looks like:
```
postgresql://user:password@host:5432/dbname
```

### Step 2 — Deploy on Render
1. Go to https://render.com → **New** → **Blueprint** → connect your GitHub repo.
2. Render detects `render.yaml` and creates the web service automatically.
3. In the Render dashboard, set these environment variables for the web service:
   - `DATABASE_URL` — the PostgreSQL connection string from Step 1
   - `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_DEFAULT_SENDER`
   - `CLIENT_ID`, `CLIENT_SECRET`
4. Click **Apply** to deploy.

> `SECRET_KEY`, `SESSION_FILE_DIR`, and `SESSION_COOKIE_SECURE` are already configured by `render.yaml`.

### Step 3 — Update Google OAuth redirect URI
Add your Render URL to the allowed redirect URIs in Google Cloud Console:
```
https://<your-app>.onrender.com/auth/callback
```

---

## 📋 Usage Guidelines
- **Logging In:** Use your credentials to log in to the application.
- **Upload Excel file:** Upload the file found at `example/Student_Marksheet_50_Students.xlsx`, then click **Upload and Validate**.
- **Generating Result:** After uploading, scroll down and click **Process Results**.

**To see screenshots, open the `/screenshots/` folder.**
