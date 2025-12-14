from flask import Flask, render_template, request, redirect, flash, session
import sqlite3, random, smtplib, time
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ===============================
# EMAIL CONFIG (TESTING PURPOSE)
# ===============================
EMAIL_ADDRESS = "testmail.28.11.a@gmail.com"
EMAIL_PASSWORD = "dwvfwermlwkynxpz"   # 16-char app password (no spaces)

# ===============================
# ADMIN CREDENTIALS
# ===============================
ADMIN_EMAIL = "admin@gmail.com"
ADMIN_PASSWORD = "admin123"

# ===============================
# DATABASE
# ===============================
def get_db():
    return sqlite3.connect("users.db")

with get_db() as db:
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)

# ===============================
# OTP EMAIL FUNCTION
# ===============================
def send_otp(email, otp):
    try:
        msg = MIMEText(f"Your OTP is: {otp}")
        msg["Subject"] = "OTP Verification"
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = email

        server = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10)
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print("Email error:", e)
        return False

# ===============================
# USER ROUTES
# ===============================
@app.route("/")
def login():
    return render_template("login.html")

@app.route("/register")
def register():
    return render_template("register.html")

@app.route("/register_user", methods=["POST"])
def register_user():
    email = request.form["email"]
    password = request.form["password"]
    confirm = request.form["confirm"]

    if password != confirm:
        flash("Passwords do not match", "error")
        return redirect("/register")

    otp = random.randint(100000, 999999)

    session["temp_user"] = {
        "email": email,
        "password": generate_password_hash(password),
        "otp": otp,
        "otp_time": time.time()
    }

    if not send_otp(email, otp):
        flash("OTP service unavailable", "error")
        return redirect("/register")

    flash("OTP sent to your email", "success")
    return redirect("/verify")

@app.route("/verify")
def verify():
    return render_template("verify_otp.html")

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    user_otp = request.form["otp"]
    data = session.get("temp_user")

    if not data:
        flash("Session expired. Register again.", "error")
        return redirect("/register")

    # OTP expiry (5 minutes)
    if time.time() - data["otp_time"] > 300:
        flash("OTP expired. Please resend OTP.", "error")
        return redirect("/verify")

    if str(data["otp"]) == user_otp:
        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users (email, password) VALUES (?, ?)",
                    (data["email"], data["password"])
                )
            session.pop("temp_user")
            flash("Registration successful", "success")
            return redirect("/")
        except:
            flash("Account already exists", "error")
            return redirect("/register")
    else:
        flash("Invalid OTP", "error")
        return redirect("/verify")

# ===============================
# RESEND OTP
# ===============================
@app.route("/resend_otp")
def resend_otp():
    data = session.get("temp_user")

    if not data:
        flash("Session expired. Register again.", "error")
        return redirect("/register")

    new_otp = random.randint(100000, 999999)
    data["otp"] = new_otp
    data["otp_time"] = time.time()
    session["temp_user"] = data

    send_otp(data["email"], new_otp)

    flash("New OTP sent to your email", "success")
    return redirect("/verify")

# ===============================
# LOGIN
# ===============================
@app.route("/login_user", methods=["POST"])
def login_user():
    email = request.form["email"]
    password = request.form["password"]

    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE email=?",
            (email,)
        ).fetchone()

    if user and check_password_hash(user[2], password):
        session["user"] = email
        return redirect("/dashboard")

    flash("Invalid email or password", "error")
    return redirect("/")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html", email=session["user"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ===============================
# ADMIN PANEL
# ===============================
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        if request.form["email"] == ADMIN_EMAIL and request.form["password"] == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin_panel")
        flash("Invalid admin credentials", "error")
    return render_template("admin_login.html")

@app.route("/admin_panel")
def admin_panel():
    if not session.get("admin"):
        return redirect("/admin")

    with get_db() as db:
        users = db.execute("SELECT id, email FROM users").fetchall()
        total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    return render_template(
        "admin_panel.html",
        users=users,
        total_users=total_users
    )

@app.route("/delete_user/<int:user_id>")
def delete_user(user_id):
    if session.get("admin"):
        with get_db() as db:
            db.execute("DELETE FROM users WHERE id=?", (user_id,))
    return redirect("/admin_panel")

if __name__ == "__main__":
    app.run()