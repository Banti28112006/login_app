from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3, random, smtplib
from werkzeug.security import generate_password_hash, check_password_hash
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "supersecretkey"

EMAIL_ADDRESS = "testmail.28.11.a@gmail.com"
EMAIL_PASSWORD = "bsvd rrgz vblx xnam"

ADMIN_EMAIL = "admin@gmail.com"
ADMIN_PASSWORD = "admin123"

def get_db():
    return sqlite3.connect("users.db")

# Create table
with get_db() as db:
    db.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        password TEXT
    )
    """)

# ---------- EMAIL OTP ----------
def send_otp(email, otp):
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "OTP Verification"
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = email

    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    server.send_message(msg)
    server.quit()

# ---------- USER AUTH ----------
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
        "otp": otp
    }

    send_otp(email, otp)
    flash("OTP sent to your email", "success")
    return redirect("/verify")

@app.route("/verify")
def verify():
    return render_template("verify_otp.html")

@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    user_otp = request.form["otp"]
    data = session.get("temp_user")

    if str(data["otp"]) == user_otp:
        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users (email, password) VALUES (?,?)",
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

# ---------- LOGIN ----------
@app.route("/login_user", methods=["POST"])
def login_user():
    email = request.form["email"]
    password = request.form["password"]

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()

    if user and check_password_hash(user[2], password):
        session["user"] = email
        return redirect("/dashboard")
    flash("Invalid login", "error")
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

# ---------- FORGOT PASSWORD ----------
@app.route("/forgot")
def forgot():
    return render_template("forgot.html")

@app.route("/forgot_otp", methods=["POST"])
def forgot_otp():
    email = request.form["email"]
    otp = random.randint(100000, 999999)
    session["reset"] = {"email": email, "otp": otp}
    send_otp(email, otp)
    return redirect("/reset")

@app.route("/reset")
def reset():
    return render_template("reset.html")

@app.route("/reset_password", methods=["POST"])
def reset_password():
    otp = request.form["otp"]
    new_pass = generate_password_hash(request.form["password"])

    if str(session["reset"]["otp"]) == otp:
        with get_db() as db:
            db.execute(
                "UPDATE users SET password=? WHERE email=?",
                (new_pass, session["reset"]["email"])
            )
        session.pop("reset")
        flash("Password reset successful", "success")
        return redirect("/")
    flash("Invalid OTP", "error")
    return redirect("/reset")

# ---------- ADMIN ----------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        if request.form["email"] == ADMIN_EMAIL and request.form["password"] == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect("/admin_panel")
        flash("Invalid admin login", "error")
    return render_template("admin_login.html")

@app.route("/admin_panel")
def admin_panel():
    if not session.get("admin"):
        return redirect("/admin")
    with get_db() as db:
        users = db.execute("SELECT id,email FROM users").fetchall()
    return render_template("admin_panel.html", users=users)

@app.route("/delete/<int:id>")
def delete(id):
    if session.get("admin"):
        with get_db() as db:
            db.execute("DELETE FROM users WHERE id=?", (id,))
    return redirect("/admin_panel")

if __name__ == "__main__":
    app.run()