import os
from fastapi import APIRouter, Request, Depends, HTTPException, Security
from fastapi.responses import RedirectResponse, JSONResponse
from app.core.auth import get_current_user
import os
import json
from urllib.parse import urlencode
from sqlalchemy.orm import Session
from app.models.user import User
from app.database import get_db
from datetime import datetime, timedelta
import requests
import logging
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

router = APIRouter()
bearer_scheme = HTTPBearer(auto_error=False)

# Utility: Get valid Gmail access token for user, refresh if needed
def get_valid_gmail_access_token(user: User, db: Session):
    """
    Returns a valid Gmail access token for the user, refreshing if expired.
    Raises HTTPException if refresh fails or tokens are missing.
    """
    print(f"[DEBUG] Checking Gmail tokens for user: {user.email}")
    print(f"[DEBUG] Current access token: {user.google_access_token}")
    print(f"[DEBUG] Current refresh token: {user.google_refresh_token}")
    print(f"[DEBUG] Token expiry: {user.google_token_expiry}")
    if not user.google_access_token or not user.google_refresh_token or not user.google_token_expiry:
        raise HTTPException(status_code=403, detail="Gmail not authorized for this user.")
    expiry = user.google_token_expiry
    if isinstance(expiry, str):
        expiry = datetime.fromisoformat(expiry)
    if expiry > datetime.utcnow() + timedelta(minutes=1):
        return user.google_access_token
    # Refresh token using unified client secret loader
    data = {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "refresh_token": user.google_refresh_token,
        "grant_type": "refresh_token"
    }
    resp = requests.post(os.getenv("GOOGLE_TOKEN_URI"), data=data)
    if resp.status_code != 200:
        logging.error(f"Failed to refresh Gmail token: {resp.text}")
        raise HTTPException(status_code=401, detail="Failed to refresh Gmail token.")
    tokens = resp.json()
    user.google_access_token = tokens["access_token"]
    expires_in = tokens.get("expires_in", 3600)
    user.google_token_expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    print(f"[DEBUG] Refreshed access token: {user.google_access_token}")
    print(f"[DEBUG] New token expiry: {user.google_token_expiry}")
    db.commit()
    return user.google_access_token

# Step 1: Redirect user to Google's OAuth 2.0 server

@router.get("/gmail/authorize", tags=["Gmail"], summary="Gmail Authorize", response_class=RedirectResponse)
def gmail_authorize():
    params = {
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI"),
        "response_type": "code",
        "scope": "openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.send",
        "access_type": "offline",
        "prompt": "consent"
    }
    url = f"{os.getenv('GOOGLE_AUTH_URI')}?{urlencode(params)}"
    print(f"[DEBUG] Redirecting to Google OAuth URL: {url}")
    return RedirectResponse(url)

# Step 2: OAuth2 callback to exchange code for tokens
@router.get("/gmail/oauth2callback", tags=["Gmail"], summary="Gmail OAuth2 Callback")
async def gmail_oauth2callback(request: Request, db: Session = Depends(get_db)):
    """
    Handles Gmail OAuth2 callback, exchanges authorization code for tokens, and stores them for the user.
    Identifies user by email from ID token or userinfo endpoint.
    """
    try:
        # Extract authorization code
        code = request.query_params.get("code")
        if not code:
            logging.error("No authorization code provided in OAuth2 callback")
            return JSONResponse({"error": "No authorization code provided"}, status_code=400)

        # Prepare token exchange request
        token_url = os.getenv("GOOGLE_TOKEN_URI", "https://oauth2.googleapis.com/token")
        data = {
            "code": code,
            "client_id": os.getenv("GOOGLE_CLIENT_ID"),
            "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
            "redirect_uri": os.getenv("GOOGLE_REDIRECT_URI"),
            "grant_type": "authorization_code"
        }

        # Exchange code for tokens
        print(f"[DEBUG] Exchanging code for tokens at {token_url}")
        token_resp = requests.post(token_url, data=data)
        print(f"[DEBUG] Token response: {token_resp.status_code} {token_resp.text}")

        if token_resp.status_code != 200:
            logging.error(f"Token exchange failed: {token_resp.text}")
            return JSONResponse({"error": f"Token exchange failed: {token_resp.text}"}, status_code=500)

        tokens = token_resp.json()
        print(f"[DEBUG] Tokens received: {tokens}")

        # Extract email from ID token or userinfo endpoint
        email = None
        id_token = tokens.get("id_token")
        if id_token:
            try:
                from google.oauth2 import id_token as google_id_token
                from google.auth.transport import requests as google_requests
                idinfo = google_id_token.verify_oauth2_token(
                    id_token, 
                    google_requests.Request(), 
                    os.getenv("GOOGLE_CLIENT_ID")
                )
                print(f"[DEBUG] Decoded id_token: {idinfo}")
                email = idinfo.get("email")
            except Exception as e:
                logging.error(f"Failed to decode id_token: {e}")
                print(f"[DEBUG] Failed to decode id_token: {e}")

        # Fallback: Use access token to get email from userinfo endpoint
        if not email and tokens.get("access_token"):
            try:
                userinfo_resp = requests.get(
                    "https://openidconnect.googleapis.com/v1/userinfo",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"}
                )
                if userinfo_resp.status_code == 200:
                    userinfo = userinfo_resp.json()
                    email = userinfo.get("email")
                    print(f"[DEBUG] Email from userinfo endpoint: {email}")
                else:
                    print(f"[DEBUG] Failed to get userinfo: {userinfo_resp.status_code} {userinfo_resp.text}")
            except Exception as e:
                print(f"[DEBUG] Exception while getting userinfo: {e}")

        if not email:
            print(f"[DEBUG] Could not determine user email from OAuth callback. Tokens: {tokens}")
            return JSONResponse({"error": "Could not determine user email from OAuth callback."}, status_code=400)

        # Store tokens in DB for user with this email
        user = db.query(User).filter(User.email == email).first()
        if not user:
            print(f"[DEBUG] No user found for email: {email}, creating new user.")
            from app.models.user import User as UserModel
            user = UserModel(
                email=email,
                hashed_password="",
                is_verified=True,
                google_access_token=tokens.get("access_token"),
                google_refresh_token=tokens.get("refresh_token"),
                google_token_expiry=datetime.utcnow() + timedelta(seconds=tokens.get("expires_in", 3600))
            )
            db.add(user)
        else:
            user.google_access_token = tokens.get("access_token")
            user.google_refresh_token = tokens.get("refresh_token")
            user.google_token_expiry = datetime.utcnow() + timedelta(seconds=tokens.get("expires_in", 3600))
        
        db.commit()
        db.refresh(user)
        print(f"[DEBUG] Gmail account linked for user: {email}")

        # Redirect to frontend or return success response
        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
        return RedirectResponse(url=f"{frontend_url}?email={email}&success=true")
    except Exception as e:
        import traceback
        logging.error(f"Failed to handle OAuth2 callback: {e}\n{traceback.format_exc()}")
        return JSONResponse({"error": f"Internal server error: {str(e)}"}, status_code=500)

@router.get("/gmail/messages")
def get_gmail_messages(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Fetches a list of the user's Gmail messages (first 10).
    """
    try:
        import google.oauth2.credentials
        import googleapiclient.discovery
        # If current_user is a string (token), fetch the user from DB
        if isinstance(current_user, str):
            user = db.query(User).filter(User.email == current_user).first()
            if not user:
                raise HTTPException(status_code=403, detail="User not found for token.")
            current_user = user
        print(f"[DEBUG] current_user: {getattr(current_user, 'email', None)}")
        token = get_valid_gmail_access_token(current_user, db)
        print(f"[DEBUG] Gmail access token: {token}")
        credentials = google.oauth2.credentials.Credentials(token)
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        print(f"[DEBUG] Gmail API messages response: {results}")
        return {"messages": messages}
    except Exception as e:
        import traceback
        logging.error(f"Failed to fetch Gmail messages: {e}\n{traceback.format_exc()}")
        return JSONResponse({"error": f"Failed to fetch Gmail messages: {e}"}, status_code=500)

@router.get("/gmail/message/{message_id}")
def get_gmail_message(message_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Fetches the details of a specific Gmail message by ID.
    Returns only necessary fields: subject, from, to, date, snippet, and body (plain text if available).
    """
    try:
        import google.oauth2.credentials
        import googleapiclient.discovery
        # If current_user is a string (token), fetch the user from DB
        if isinstance(current_user, str):
            user = db.query(User).filter(User.email == current_user).first()
            if not user:
                raise HTTPException(status_code=403, detail="User not found for token.")
            current_user = user
        print(f"[DEBUG] current_user: {getattr(current_user, 'email', None)}")
        token = get_valid_gmail_access_token(current_user, db)
        print(f"[DEBUG] Gmail access token: {token}")
        credentials = google.oauth2.credentials.Credentials(token)
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        print(f"[DEBUG] Gmail API message response: {message}")
        headers = message.get('payload', {}).get('headers', [])
        def get_header(name):
            for h in headers:
                if h['name'].lower() == name.lower():
                    return h['value']
            return None
        subject = get_header('Subject')
        sender = get_header('From')
        to = get_header('To')
        date = get_header('Date')
        snippet = message.get('snippet')
        # Extract plain text body if available
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
        return {
            'id': message.get('id'),
            'threadId': message.get('threadId'),
            'subject': subject,
            'from': sender,
            'to': to,
            'date': date,
            'snippet': snippet,
            'body': body
        }
    except Exception as e:
        import traceback
        logging.error(f"Failed to fetch Gmail message: {e}\n{traceback.format_exc()}")
        return JSONResponse({"error": f"Failed to fetch Gmail message: {e}"}, status_code=500)

@router.get("/gmail/profile")
def get_gmail_profile(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Fetches the Gmail profile of the authenticated user.
    """
    try:
        import google.oauth2.credentials
        import googleapiclient.discovery
        token = get_valid_gmail_access_token(current_user, db)
        credentials = google.oauth2.credentials.Credentials(token)
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
        profile = service.users().getProfile(userId='me').execute()
        return profile
    except Exception as e:
        logging.error(f"Failed to fetch Gmail profile: {e}")
        return JSONResponse({"error": "Failed to fetch Gmail profile."}, status_code=500)

@router.post("/gmail/ai-reply/{message_id}")
def ai_reply_to_email(message_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """
    Generate an AI reply for a specific Gmail message by its ID.
    The reply will be a direct summary of the email content, not a generic or instructional sentence.
    """
    try:
        import base64
        from app.services.summarizer import summarize_email
        from app.services.reply_generator import generate_reply
        import google.oauth2.credentials
        import googleapiclient.discovery
        import re
        # If current_user is a string (token), fetch the user from DB
        if isinstance(current_user, str):
            user = db.query(User).filter(User.email == current_user).first()
            if not user:
                raise HTTPException(status_code=403, detail="User not found for token.")
            current_user = user
        print(f"[DEBUG] current_user: {getattr(current_user, 'email', None)}")
        token = get_valid_gmail_access_token(current_user, db)
        print(f"[DEBUG] Gmail access token: {token}")
        credentials = google.oauth2.credentials.Credentials(token)
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        print(f"[DEBUG] Gmail API message response: {message}")
        # Extract plain text body
        def get_body(payload):
            if payload.get('mimeType') == 'text/plain' and 'data' in payload.get('body', {}):
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
        print(f"[DEBUG] Email body for AI: {body}")
        # Defensive: If summarize_email or generate_reply fail, catch and log
        try:
            summary = summarize_email(body)
            print(f"[DEBUG] Email summary: {summary}")
        except Exception as e:
            print(f"[DEBUG] Error in summarize_email: {e}")
            summary = ""
        try:
            reply = generate_reply(summary)
            print(f"[DEBUG] AI reply: {reply}")
        except Exception as e:
            print(f"[DEBUG] Error in generate_reply: {e}")
            reply = ""
        # Remove generic/instructional lines from reply
        if reply:
            # Remove lines that look like instructions or generic help
            lines = [line for line in reply.split('\n') if not re.search(r'summarize|happy to help|here is|as requested|let me|i can|i will|i have|please find|below is|following is|sure,|certainly|of course', line, re.IGNORECASE)]
            # Remove empty lines and strip
            lines = [line.strip() for line in lines if line.strip()]
            # If nothing left, fallback to summary
            if not lines:
                reply = summary
            else:
                reply = '\n'.join(lines)
        else:
            reply = summary
        # Limit to 2-3 lines
        reply_lines = [line.strip() for line in reply.split('\n') if line.strip()]
        reply = '\n'.join(reply_lines[:3])
        return {
            'message_id': message_id,
            'summary': summary,
            'reply': reply
        }
    except Exception as e:
        import traceback
        logging.error(f"Failed to generate AI reply: {e}\n{traceback.format_exc()}")
        return JSONResponse({"error": f"Failed to generate AI reply: {e}"}, status_code=500)

# --- REMOVE email_content param from summarize route, only use id and token ---
@router.post("/summarize")
def summarize_gmail_message(id: str, token: str, db: Session = Depends(get_db)):
    """
    Summarize a Gmail message by its ID for the authenticated user (token).
    Returns a 2-3 line summary of the email body.
    """
    try:
        from app.services.summarizer import summarize_email
        import google.oauth2.credentials
        import googleapiclient.discovery
        from app.core.auth import get_current_user
        import base64
        import json as _json
        import os
        # Find user by token (JWT)
        user = get_current_user(token=token, db=db)
        if isinstance(user, str):
            user = db.query(User).filter(User.email == user).first()
        if not user:
            raise HTTPException(status_code=403, detail="User not found for token.")
        # Load client secrets once
        from app.services.email_reader import load_client_secrets
        client_secrets = load_client_secrets()
        # Get valid Gmail access token
        gmail_token = get_valid_gmail_access_token(user, db)
        credentials = google.oauth2.credentials.Credentials(
            gmail_token,
            refresh_token=user.google_refresh_token,
            token_uri=client_secrets["token_uri"],
            client_id=client_secrets["client_id"],
            client_secret=client_secrets["client_secret"]
        )
        service = googleapiclient.discovery.build('gmail', 'v1', credentials=credentials)
        message = service.users().messages().get(userId='me', id=id, format='full').execute()
        # Extract plain text body (robust)
        def get_body(payload):
            if payload.get('mimeType') == 'text/plain' and 'data' in payload.get('body', {}):
                return base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
            elif 'parts' in payload:
                for part in payload['parts']:
                    body = get_body(part)
                    if body:
                        return body
            return None
        body = get_body(message.get('payload', {}))
        if not body:
            # Try to extract text from HTML if plain text is missing
            def extract_text_from_html(payload):
                if payload.get('mimeType') == 'text/html' and 'data' in payload.get('body', {}):
                    html = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
                    # Simple HTML to text
                    import re
                    text = re.sub('<[^<]+?>', '', html)
                    return text
                elif 'parts' in payload:
                    for part in payload['parts']:
                        text = extract_text_from_html(part)
                        if text:
                            return text
                return None
            body = extract_text_from_html(message.get('payload', {}))
        if not body:
            body = message.get('snippet', '')
        # Defensive: fallback if body is still empty
        if not body:
            return {"id": id, "summary": "No content found in email."}
        # Summarize to 2-3 lines
        summary = summarize_email(body)
        # If summarize_email returns a long summary, trim to 2-3 lines
        summary_lines = [line.strip() for line in summary.split('\n') if line.strip()]
        summary = '\n'.join(summary_lines[:3])
        return {"id": id, "summary": summary}
    except Exception as e:
        import traceback
        logging.error(f"Failed to summarize Gmail message: {e}\n{traceback.format_exc()}")
        return JSONResponse({"error": f"Failed to summarize Gmail message: {e}"}, status_code=500)
