
import firebase_admin
from firebase_admin import credentials
import os

# Get the credentials file path from the environment variable
firebase_credentials = os.environ.get("FIREBASE_CREDENTIALS")

# If the path is not absolute, make it relative to the project root
if firebase_credentials and not os.path.isabs(firebase_credentials):
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    firebase_credentials = os.path.join(project_root, firebase_credentials)

# Fallback to default if not set
if not firebase_credentials:
    firebase_credentials = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "email-ai-agent-232b5-firebase-adminsdk-fbsvc-4dfabb18aa.json")

if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_credentials)
    firebase_admin.initialize_app(cred)
