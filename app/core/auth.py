from fastapi import Depends, HTTPException, Header
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt

from app.models.user import User
from app.database import get_db
from app.core.security import (
    verify_password,
    create_access_token,
    SECRET_KEY,
    ALGORITHM,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def authenticate_user(db: Session, email: str, password: str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password):
        return False
    return user


def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


def get_current_user(
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = None
    if authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]
    # Fallback to cookie if header is missing
    if not token:
        import inspect
        from fastapi import Request
        frame = inspect.currentframe().f_back
        request = None
        while frame:
            local_vars = frame.f_locals
            if 'request' in local_vars and isinstance(local_vars['request'], Request):
                request = local_vars['request']
                break
            frame = frame.f_back
        if request:
            token = request.cookies.get("access_token")
    if not token:
        raise credentials_exception
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        print(f"User not found for email: {email}")
        raise credentials_exception
    print(f"Authenticated user: {user.email}")
    return user