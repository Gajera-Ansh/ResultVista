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
from flask_sqlalchemy import SQLAlchemy
from database import db, User
from authlib.integrations.flask_client import OAuth


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
app.config["SECRET_KEY"] = "4227"
bcrypt = Bcrypt(app)

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
                **form_data
            )

        # check password length
        if len(password) < 8:
            return render_template(
                "register.html",
                error="Password must be at least 8 characters long",
                **form_data
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


@app.route("/dashboard")
def dashboard():

    # check if user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

    # fetch user details
    user = User.query.get(session["user_id"])

    # if user not found, clear session and redirect to login
    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html")


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


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
