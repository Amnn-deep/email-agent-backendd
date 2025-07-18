import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

def send_verification_email(to_email: str, verification_token: str):
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER", "deepaman47577@gmail.com")
    smtp_password = os.getenv("SMTP_PASSWORD", "jsci drpe rkat enns")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    verify_url = f"http://localhost:8000/verify-email?token={verification_token}"
    subject = "Verify your email address"
    body = f"""
    <p>Thank you for registering!</p>
    <p>Please verify your email by clicking the link below:</p>
    <a href='{verify_url}'>Verify Email</a>
    <p>If you did not request this, you can ignore this email.</p>
    """

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "html"))

    try:
        print(f"Connecting to SMTP server {smtp_server}:{smtp_port} as {smtp_user}")
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.set_debuglevel(1)
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_email, to_email, msg.as_string())
        print(f"Verification email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send verification email: {e}")
        raise
