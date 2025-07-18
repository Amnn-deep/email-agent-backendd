import firebase_admin
from firebase_admin import credentials
import os

# Use the correct path to your service account JSON file
FIREBASE_CREDENTIALS = os.getenv("FIREBASE_CREDENTIALS_JSON")
if not FIREBASE_CREDENTIALS:
    # fallback to local file if env var not set
    FIREBASE_CREDENTIALS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "email-ai-agent-232b5-firebase-adminsdk-fbsvc-4dfabb18aa.json")

if not firebase_admin._apps:
    cred = credentials.Certificate(FIREBASE_CREDENTIALS)
    firebase_admin.initialize_app(cred)
