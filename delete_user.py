from app.database import SessionLocal
from app.models.user import User

# Change this email to the one you want to delete
target_email = "deepaman37377@gmail.com"

def delete_user_by_email(email: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user:
            db.delete(user)
            db.commit()
            print(f"Deleted user: {email}")
        else:
            print(f"No user found with email: {email}")
    finally:
        db.close()

if __name__ == "__main__":
    delete_user_by_email(target_email)
