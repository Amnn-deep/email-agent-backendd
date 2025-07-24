import os
from typing import List
import google.oauth2.credentials
import googleapiclient.discovery
from app.models.user import User
from sqlalchemy.orm import Session

def fetch_daily_emails(current_user: User, db: Session) -> List[str]:
    """
    Fetch the latest 10 email subjects from the user's Gmail using OAuth token.
    """
    if not current_user.google_access_token or not current_user.google_refresh_token:
        return []
    try:
        credentials = google.oauth2.credentials.Credentials(
            current_user.google_access_token,
            refresh_token=current_user.google_refresh_token,
            token_uri=os.getenv("GOOGLE_TOKEN_URI"),
            client_id=os.getenv("GOOGLE_CLIENT_ID"),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET")
        )
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        subjects = []
        for msg in messages:
            msg_detail = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['Subject']).execute()
            headers = msg_detail.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
            subjects.append(subject)
        return subjects
    except Exception as e:
        print(f"[ERROR] Failed to fetch Gmail emails: {e}")
        return []