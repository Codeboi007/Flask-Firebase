from firebase_admin import  auth, firestore
from flask import Flask, session, redirect, url_for, request, render_template, jsonify
from flask_cors import CORS # type: ignore
import os
from routes.auth_routes import auth_bp

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session
CORS(app, supports_credentials=True)
app.register_blueprint(auth_bp, url_prefix='/auth')
# Login route
@app.route("/")
def login():
    return render_template("login.html")

# Signup route
@app.route("/signup")
def signup():
    return render_template("signup.html")

# Welcome route (protected)
@app.route("/welcome")
def welcome():
    if "user" in session:
        return render_template("welcome.html", **session["user"])
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)