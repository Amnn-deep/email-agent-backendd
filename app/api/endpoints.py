from fastapi import APIRouter, Depends, HTTPException, Query
from app.core.auth import get_current_user
from app.services.email_reader import fetch_daily_emails
from sqlalchemy.orm import Session
from app.database import get_db
from app.services.summarizer import summarize_email
from app.services.reply_generator import generate_reply
from typing import List, Optional
import google.oauth2.credentials
import googleapiclient.discovery

router = APIRouter()

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
async def reply_to_last_email(current_user: str = Depends(get_current_user)):
    try:
        emails = fetch_daily_emails(current_user)
        if not emails:
            raise HTTPException(status_code=404, detail="No emails found.")
        last_email = emails[-1]
        summary = summarize_email(last_email)
        reply = generate_reply(summary)
        return {"last_email": last_email, "summary": summary, "reply": reply}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))