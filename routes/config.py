import firebase_admin
from firebase_admin import credentials, firestore
from flask import Blueprint
import requests

config_bp=Blueprint('config',__name__)

# Initialize Firebase Admin SDK
cred = credentials.Certificate('flask-f81f6-firebase-adminsdk-fbsvc-35a9d7acaf.json')
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