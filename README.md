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
   Create a `.env` file in the root directory and add the necessary configuration variables as per the `.env.example` file.

4. **Database setup:**
   open XAMPP and create a database **user**.

6. **Run the project:**
   run app.py file and click on the first link

## Deployment

### Deploy to Render.com (recommended)
1. Push your code to GitHub.
2. Go to [render.com](https://render.com) and create a new **Web Service**.
3. Connect your GitHub repository.
4. Render will automatically detect `render.yaml` and configure the service.
5. Add the following environment variables in the Render dashboard:
   - `DATABASE_URL` – Your MySQL connection string (e.g. from [PlanetScale](https://planetscale.com) or [Railway](https://railway.app)): `mysql+pymysql://user:password@host:3306/dbname`
   - `SECRET_KEY` – A long random secret string
   - `MAIL_USERNAME` – Your Gmail address
   - `MAIL_PASSWORD` – Your Gmail [App Password](https://myaccount.google.com/apppasswords)
   - `MAIL_DEFAULT_SENDER` – Your Gmail address
   - `CLIENT_ID` – Google OAuth Client ID
   - `CLIENT_SECRET` – Google OAuth Client Secret
   - `SESSION_FILE_DIR` – `/tmp/flask_session`
6. Click **Deploy**.

### Deploy to Railway
1. Push your code to GitHub.
2. Go to [railway.app](https://railway.app) and create a new project from your GitHub repo.
3. Add a **MySQL** plugin to the project; Railway will provide a `DATABASE_URL`.
4. Set the remaining environment variables (same list as above).
5. Railway will use the `Procfile` to start the app with `gunicorn`.

### Google OAuth – Authorized Redirect URI
After deploying, update your Google Cloud Console OAuth credentials to add your production URL as an authorized redirect URI:
```
https://<your-app-domain>/auth/callback
```

## Usage Guidelines
- **Logging In:** Use your credentials to log into the application. 
- **Upload excel file:** Upload excel file which in **example/Student_Marksheet_50_Students.xlsx** than click on **upload and validate** button
- **Generating Result:** after clicking on **upload and validate** button scroll down and click on **Process Results**

**To see screenshots open /screenshots/ folder**
