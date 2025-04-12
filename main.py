import firebase_admin
from firebase_admin import credentials, auth, firestore
from flask import Flask, session, redirect, url_for, request, render_template, jsonify
import requests
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session

# Initialize Firebase Admin SDK
cred = credentials.Certificate('instance/flask-f81f6-firebase-adminsdk-fbsvc-cdfa7b61d0.json')
firebase_admin.initialize_app(cred, {
    'projectId': 'flask-f81f6',
    'storageBucket': 'flask-f81f6.appspot.com'
})
db = firestore.client()

# Use environment variable for API key (replace with your actual key)
FIREBASE_WEB_API_KEY = 'AIzaSyDRW_XVHzGuTkaO_LKQYw6sz7IZF0LiAAY'

# Helper function for Firebase sign-in
def sign_in_with_email_password(email, password):
    response = requests.post(
        f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}",
        json={"email": email, "password": password, "returnSecureToken": True}
    )
    response.raise_for_status()
    return response.json()

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

# Handle login POST request
@app.route("/login", methods=["POST"])
def handle_login():
    email = request.form.get("email")
    password = request.form.get("password")
    
    try:
        # Validate email format
        if not email or '@' not in email:
            raise ValueError("Invalid email format")
            
        # Sign in user
        data = sign_in_with_email_password(email, password)
        
        # Get user details from Admin SDK
        user = auth.get_user(data['localId'])
        
        # Store user info in session
        session["user"] = {
            "uid": data["localId"],
            "email": data["email"],
            "name": user.display_name or "User",
            "id_token": data["idToken"]
        }
        return redirect(url_for("welcome"))
    
    except requests.exceptions.HTTPError as e:
        error_response = e.response.json()['error']
        return jsonify({"error": error_response['message']}), 401
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Handle signup POST request
@app.route("/register", methods=["POST"])
def handle_register():
    email = request.form.get("email")
    password = request.form.get("password")
    name = request.form.get("name")
    
    try:
        # Validate inputs
        if not email or '@' not in email:
            raise ValueError("Invalid email format")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters")
            
        # Create user in Firebase Auth
        user = auth.create_user(
            email=email,
            password=password,
            display_name=name
        )
        
        # Store additional data in Firestore
        db.collection("users").document(user.uid).set({
            "name": name,
            "email": email,
            "created_at": firestore.SERVER_TIMESTAMP
        })
        
        # Auto-login user
        data = sign_in_with_email_password(email, password)
        
        session["user"] = {
            "uid": data["localId"],
            "email": data["email"],
            "name": name,
            "id_token": data["idToken"]
        }
        return redirect(url_for("welcome"))
    
    except requests.exceptions.HTTPError as e:
        error_response = e.response.json()['error']
        return jsonify({"error": error_response['message']}), 400
    
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/verify-google-token', methods=['POST'])
def verify_google_token():
    try:
        # Get the ID token from the client
        id_token = request.json.get('token')
        if not id_token:
            return jsonify({'error': 'Token required'}), 400

        # Verify the token with Firebase Admin
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        email = decoded_token['email']
        name = decoded_token.get('name', 'User')

        # Check if user exists in Firestore (optional)
        user_doc = db.collection('users').document(uid).get()
        if not user_doc.exists:
            # Create user in Firestore if not exists
            db.collection('users').document(uid).set({
                'name': name,
                'email': email,
                'created_at': firestore.SERVER_TIMESTAMP
            })

        # Store user info in session
        session['user'] = {
            'uid': uid,
            'email': email,
            'name': name,
            'id_token': id_token
        }
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 401

# Logout route
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)