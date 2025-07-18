
import firebase_admin
from firebase_admin import credentials
import os
import json
import base64

# Try to load base64-encoded credentials from env (for serverless/cloud)
firebase_credentials_b64 = os.environ.get("FIREBASE_CREDENTIALS_JSON")
cred_obj = None

if firebase_credentials_b64:
    try:
        cred_json = base64.b64decode(firebase_credentials_b64).decode("utf-8")
        cred_obj = json.loads(cred_json)
    except Exception as e:
        raise RuntimeError("Failed to decode FIREBASE_CREDENTIALS_JSON: %s" % e)

if cred_obj:
    cred = credentials.Certificate(cred_obj)
else:
    # Fallback to file path (for local dev)
    firebase_credentials = os.environ.get("FIREBASE_CREDENTIALS")
    if firebase_credentials and not os.path.isabs(firebase_credentials):
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        firebase_credentials = os.path.join(project_root, firebase_credentials)
    if not firebase_credentials:
        firebase_credentials = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "email-ai-agent-232b5-firebase-adminsdk-fbsvc-4dfabb18aa.json")
    cred = credentials.Certificate(firebase_credentials)

if not firebase_admin._apps:
    firebase_admin.initialize_app(cred)
