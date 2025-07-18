from fastapi import APIRouter, Depends, HTTPException, status, Query, Body, Response
from sqlalchemy.orm import Session
from app.models.user import User
from app.database import get_db
from app.core.security import get_password_hash, verify_password, create_access_token
from pydantic import BaseModel
from datetime import timedelta
import uuid
from app.services.email_sender import send_verification_email
from app.services.firebase_admin_init import firebase_admin
from firebase_admin import auth as firebase_auth
import firebase_admin.exceptions
from typing import Optional

router = APIRouter()

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class FirebaseTokenRequest(BaseModel):
    firebase_id_token: str
    google_access_token: Optional[str] = None

@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        hashed_password = get_password_hash(user.password)
        verification_token = str(uuid.uuid4())
        new_user = User(email=user.email, hashed_password=hashed_password, is_verified=False, verification_token=verification_token)
        db.add(new_user)
        try:
            send_verification_email(user.email, verification_token)
        except Exception as email_error:
            print(f"Warning: Could not send verification email: {email_error}")
        db.commit()
        db.refresh(new_user)
        # Return the verification token in the response for testing purposes
        return {
            "msg": "User registered successfully. Please check your email to verify your account.",
            "verification_token": verification_token,
            "verification_url": f"http://localhost:8000/verify-email?token={verification_token}"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@router.get("/verify-email")
def verify_email(token: str = Query(...), db: Session = Depends(get_db)):
    print(f"[DEBUG] Received verification token: {token}")
    user = db.query(User).filter(User.verification_token == token).first()
    print(f"[DEBUG] User query result: {user}")
    if not user:
        # Print all users and their tokens for debugging
        all_users = db.query(User).all()
        print("[DEBUG] All users and their verification tokens:")
        for u in all_users:
            print(f"Email: {u.email}, Token: {u.verification_token}, Verified: {u.is_verified}")
        print(f"[DEBUG] No user found for token: {token}")
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    print(f"[DEBUG] Verifying user: {user.email}")
    user.is_verified = True
    user.verification_token = None
    db.commit()
    print(f"[DEBUG] User {user.email} verified successfully.")
    return {"msg": "Email verified successfully. You can now log in."}

@router.post("/token")
def login(user: UserLogin, db: Session = Depends(get_db), response: Response = None):
    try:
        db_user = db.query(User).filter(User.email == user.email).first()
        if not db_user or not verify_password(user.password, db_user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect email or password")
        if not db_user.is_verified:
            raise HTTPException(status_code=403, detail="Email not verified. Please verify your email before logging in.")
        access_token = create_access_token(
            data={"sub": db_user.email},
            expires_delta=timedelta(minutes=60)
        )
        # Set JWT as HttpOnly cookie for browser-based OAuth
        if response is not None:
            response.set_cookie(key="access_token", value=access_token, httponly=True, max_age=3600)
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/resend-verification")
def resend_verification(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_verified:
        return {"msg": "Email is already verified."}
    # Generate a new token
    import uuid
    user.verification_token = str(uuid.uuid4())
    db.commit()
    try:
        send_verification_email(user.email, user.verification_token)
    except Exception as email_error:
        print(f"Warning: Could not send verification email: {email_error}")
    return {"msg": "Verification email resent. Please check your inbox."}

@router.post("/register/firebase")
def firebase_register(user: UserCreate, db: Session = Depends(get_db)):
    try:
        # Create user in Firebase
        firebase_user = firebase_auth.create_user(
            email=user.email,
            password=user.password,
            email_verified=False
        )
        # Optionally, also create in local DB for extra info
        db_user = db.query(User).filter(User.email == user.email).first()
        if db_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        hashed_password = get_password_hash(user.password)
        verification_token = str(uuid.uuid4())
        new_user = User(email=user.email, hashed_password=hashed_password, is_verified=False, verification_token=verification_token)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"msg": "User registered in Firebase. Please verify your email."}
    except firebase_auth.EmailAlreadyExistsError:
        raise HTTPException(status_code=400, detail="Email already registered in Firebase")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/token/firebase")
def firebase_login(user: UserLogin):
    try:
        # Firebase does not provide direct password verification in Admin SDK
        # In production, use Firebase client SDK on frontend for login and send ID token to backend
        # Here, just check if user exists in Firebase
        firebase_user = firebase_auth.get_user_by_email(user.email)
        if not firebase_user.email_verified:
            raise HTTPException(status_code=403, detail="Email not verified in Firebase.")
        # You may want to verify password using custom logic or rely on frontend
        return {"msg": "Firebase user exists and is verified. Use client SDK for full login flow."}
    except firebase_auth.UserNotFoundError:
        raise HTTPException(status_code=400, detail="User not found in Firebase")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/firebase/verify-token")
def verify_firebase_token(
    payload: FirebaseTokenRequest = Body(...),
    db: Session = Depends(get_db)
):
    """
    Verifies a Firebase ID token and (optionally) stores the Google OAuth access token for Gmail API access.
    """
    try:
        decoded_token = firebase_auth.verify_id_token(payload.firebase_id_token)
        email = decoded_token.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="No email in Firebase token.")
        # Optionally, store Google access token in DB (extend User model if needed)
        db_user = db.query(User).filter(User.email == email).first()
        if not db_user:
            db_user = User(email=email, hashed_password="", is_verified=True)
            # Store Google access token if provided
            if payload.google_access_token:
                db_user.google_access_token = payload.google_access_token
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
        else:
            # Update Google access token if provided
            if payload.google_access_token:
                db_user.google_access_token = payload.google_access_token
                db.commit()
        return {"msg": "Firebase token verified", "email": email}
    except firebase_admin.exceptions.FirebaseError as e:
        raise HTTPException(status_code=401, detail=f"Firebase token invalid: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/admin/delete-user")
def admin_delete_user(email: str = Query(...), db: Session = Depends(get_db)):
    """
    DEV/TEST ONLY: Delete a user by email. Use for resetting test users.
    """
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"detail": f"User {email} deleted."}
