from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from app.api.endpoints import router as api_router
from app.api.auth_routes import router as auth_router
from app.api.gmail_oauth import router as gmail_oauth_router  # Add this import
from app.database import Base, engine, get_db
from sqlalchemy.orm import Session
from app.models.user import User

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create tables if they do not exist
Base.metadata.create_all(bind=engine)

app.include_router(api_router)
app.include_router(auth_router)
app.include_router(gmail_oauth_router)  # Add this line

@app.get("/")
async def read_root():
    return {"message": "Welcome to the FastAPI Email Agent!"}
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return "", 204

@app.get("/.well-known/appspecific/com.chrome.devtools.json", include_in_schema=False)
async def chrome_devtools():
    return "", 204

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="FastAPI Email Agent",
        version="1.0.0",
        description="API for email agent",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.delete("/reset-gmail-tokens/{user_email}")
def reset_gmail_tokens(user_email: str, db: Session = Depends(get_db)):
    """
    Deletes Gmail tokens for a user so they can re-authenticate with correct scopes.
    """
    user = db.query(User).filter(User.email == user_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.google_access_token = None
    user.google_refresh_token = None
    user.google_token_expiry = None
    db.commit()
    return {"success": True, "message": f"Gmail tokens reset for {user_email}. Please re-link your Gmail account."}