
from fastapi import APIRouter, Depends, HTTPException, Query, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.core.auth import get_current_user
from app.models.user import User
from app.services.email_reader import fetch_daily_emails
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.summarizer import summarize_email
from app.services.reply_generator import generate_reply
from typing import List, Optional
import google.oauth2.credentials
import googleapiclient.discovery

router = APIRouter()
bearer_scheme = HTTPBearer(auto_error=False)

@router.get("/gmail/messages")
async def get_gmail_messages(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: Session = Depends(get_db)
):
    """
    Fetch Gmail messages using Bearer token from Authorization header.
    """
    if not credentials or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    token = credentials.credentials
    try:
        credentials_obj = google.oauth2.credentials.Credentials(token)
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials_obj)
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        return {"messages": messages}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Could not validate credentials: {str(e)}")

@router.get("/emails", response_model=List[str])
async def read_emails(current_user: str = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        emails = fetch_daily_emails(current_user, db)
        if not emails:
            raise HTTPException(status_code=404, detail="No emails found.")
        return emails
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/summarize")
async def summarize_email_content(
    email_content: Optional[str] = None,
    id: Optional[str] = Query(None, description="Gmail message id"),
    token: Optional[str] = Query(None, description="Gmail OAuth token"),
    current_user: str = Depends(get_current_user)
):
    try:
        # Only use email_content if it is not None and not empty/whitespace
        if email_content is not None and str(email_content).strip() != "":
            summary = summarize_email(email_content)
            return {"summary": summary}
        elif id and token:
            credentials = google.oauth2.credentials.Credentials(token)
            service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
            message = service.users().messages().get(userId='me', id=id, format='full').execute()
            def get_body(payload):
                if payload.get('mimeType') == 'text/plain' and 'data' in payload.get('body', {}):
                    import base64
                    return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
                elif 'parts' in payload:
                    for part in payload['parts']:
                        body = get_body(part)
                        if body:
                            return body
                return None
            body = get_body(message.get('payload', {}))
            if not body:
                body = message.get('snippet', '')
            summary = summarize_email(body)
            return {"summary": summary}
        else:
            raise HTTPException(status_code=400, detail="Provide either non-empty email_content or both id and token.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reply")
async def reply_to_last_email(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        # Fetch the latest Gmail message ID
        import google.oauth2.credentials
        import googleapiclient.discovery
        if not current_user.google_access_token:
            raise HTTPException(status_code=403, detail="Gmail not connected.")
        credentials = google.oauth2.credentials.Credentials(current_user.google_access_token)
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
        results = service.users().messages().list(userId='me', maxResults=1).execute()
        messages = results.get('messages', [])
        if not messages:
            raise HTTPException(status_code=404, detail="No emails found.")
        last_msg_id = messages[0]['id']
        # Fetch the full message
        message = service.users().messages().get(userId='me', id=last_msg_id, format='full').execute()
        def get_body(payload):
            if payload.get('mimeType') == 'text/plain' and 'data' in payload.get('body', {}):
                import base64
                return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
            elif 'parts' in payload:
                for part in payload['parts']:
                    body = get_body(part)
                    if body:
                        return body
            return None
        body = get_body(message.get('payload', {}))
        if not body:
            body = message.get('snippet', '')
        summary = summarize_email(body)
        reply = generate_reply(summary)
        return {"last_email": body, "summary": summary, "reply": reply}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))