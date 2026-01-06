from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    make_response,
)
from flask_bcrypt import Bcrypt
from database import db, User
from authlib.integrations.flask_client import OAuth
import os
import pandas as pd
from werkzeug.utils import secure_filename
import uuid

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
app.config["SECRET_KEY"] = "4227"
bcrypt = Bcrypt(app)

app.config["UPLOAD_FOLDER"] = "uploads"
app.config["ALLOWED_EXTENSIONS"] = {"xlsx", "xls"}

db.init_app(app)

with app.app_context():
    db.create_all()

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id="558733018158-utoo4fupr8h2eb5tm763g3i3r0kq15sv.apps.googleusercontent.com",
    client_secret="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",
    access_token_url="https://oauth2.googleapis.com/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    api_base_url="https://www.googleapis.com/oauth2/v2/",
    client_kwargs={"scope": "email profile"},
)


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/google-register")
def google_register():
    redirect_uri = url_for("auth_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def auth_callback():
    token = google.authorize_access_token()
    resp = google.get("userinfo", token=token)
    user_info = resp.json()

    password = user_info["id"]
    name = user_info["name"]
    email = user_info.get("email")
    picture = user_info.get("picture")

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        session["user_id"] = existing_user.id
        session["login_success"] = True
    else:
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User(
            password=hashed_password,
            name=name,
            email=email,
            picture=picture,
        )
        db.session.add(user)
        db.session.commit()
        session["user_id"] = user.id

    return redirect(url_for("dashboard"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("mail")
        password = request.form.get("password")
        ConPassword = request.form.get("ConPassword")

        # Store form data to pass back on error
        form_data = {"name": name, "email": email}

        # check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return render_template(
                "register.html",
                error="User with this email already exists",
                **form_data,
            )

        # check password length
        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must be at least 8 characters long",
                **form_data,
            )

        # check if passwords match
        if password != ConPassword:
            return render_template(
                "register.html", error="Passwords do not match", **form_data
            )

        # if all validations pass, create new user
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("mail")
        password = request.form.get("password")

        # Store form data
        form_data = {"email": email}

        user = User.query.filter_by(email=email).first()

        # validate user credentials
        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["login_success"] = True
            return redirect(url_for("dashboard"))
        else:  # invalid credentials
            return render_template(
                "login.html", error="Invalid email or password", **form_data
            )

    return render_template("login.html")


@app.after_request
def add_cache_control(response):

    # Add headers to prevent caching
    if "Cache-Control" not in response.headers:
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


# Create uploads directory if it doesn't exist
if not os.path.exists(app.config["UPLOAD_FOLDER"]):
    os.makedirs(app.config["UPLOAD_FOLDER"])


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]
    )


def validate_excel_structure(df):
    """Validate the structure of the uploaded Excel file"""
    errors = []

    # Check required columns
    required_columns = ["sr. no", "enrollment number", "name"]

    # Convert column names to lowercase for comparison
    actual_columns = [str(col).strip().lower() for col in df.columns]

    # Check for required columns
    for req_col in required_columns:
        if req_col not in actual_columns:
            errors.append(f"Missing required column: '{req_col}'")

    # Check for at least one marks column
    marks_columns = [col for col in actual_columns if "marks" in col]
    if not marks_columns:
        errors.append(
            "No marks/subject columns found. Add at least one subject column."
        )

    # Check for valid data type for 'marks'
    marks_columns = [col for col in df.columns if "marks" in col.lower()]
    for col in marks_columns:
        if not pd.api.types.is_numeric_dtype(df[col]):
            errors.append(f"'{col}' column should contain numeric values")

    # Check for valid data type for 'enrollment number'
    enrollment_columns = [
        col for col in df.columns if "enrollment number" in col.lower()
    ]
    for col in enrollment_columns:
        if not pd.api.types.is_numeric_dtype(df[col]):
            errors.append("'enrollment number' column should contain numeric values")

    if errors:
        return False, errors

    return True, []


@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    # Check if user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Fetch user details
    user = User.query.get(session["user_id"])

    # If user not found, clear session and redirect to login
    if not user:
        session.clear()
        return redirect(url_for("login"))

    upload_error = None
    upload_success = None
    preview_data = None
    stats = None

    if request.method == "POST":
        # Check if the post request has the file part
        if "excel_file" not in request.files:
            upload_error = "No file selected"
        else:
            file = request.files["excel_file"]

            # If user does not select file, browser submits empty file
            if file.filename == "":
                upload_error = "No file selected"
            elif file and allowed_file(file.filename):
                # Generate unique filename
                filename = secure_filename(file.filename)
                # Get 32-char rendom hexadecimal string with simple file name
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)

                try:
                    # Save file temporarily
                    file.save(filepath)

                    file_size_mb = round(os.path.getsize(filepath) / (1024 * 1024), 2)

                    # Read Excel file
                    if filename.endswith(".xlsx"):
                        df = pd.read_excel(filepath, engine="openpyxl")
                    else:
                        df = pd.read_excel(filepath)

                    # Validate structure
                    is_valid, errors = validate_excel_structure(df)

                    if is_valid:
                        stats = {
                            "total_students": len(df),
                            "total_columns": len(df.columns),
                            "subjects": [
                                col for col in df.columns if "marks" in str(col).lower()
                            ],
                            "file_name": filename,
                            "file_size": file_size_mb,
                        }

                        # Get preview data (first 5 rows)
                        preview_data = df.head().to_dict("records")

                        # Store file info in session for processing
                        session["uploaded_file"] = filepath
                        session["file_stats"] = stats

                        upload_success = f"File '{filename}' uploaded successfully! Validated {len(df)} student records."
                    else:
                        upload_error = "Validation errors: " + ", ".join(errors)

                    # Clean up temporary file if not keeping it
                    if not is_valid:
                        if os.path.exists(filepath):
                            os.remove(filepath)

                except Exception as e:
                    upload_error = f"Error processing file: {str(e)}"
                    # Clean up if file was saved
                    if "filepath" in locals() and os.path.exists(filepath):
                        os.remove(filepath)
            else:
                upload_error = (
                    "Invalid file type. Please upload Excel files only (.xlsx, .xls)"
                )

    return render_template(
        "dashboard.html",
        user=user,
        upload_error=upload_error,
        upload_success=upload_success,
        preview_data=preview_data,
        stats=stats,
        login_success=session.pop("login_success", None),
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/delete-account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if user:
        # Delete user from database
        db.session.delete(user)
        db.session.commit()

        # Clear session
        session.clear()

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
