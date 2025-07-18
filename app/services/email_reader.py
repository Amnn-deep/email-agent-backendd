from typing import List
import imaplib
import email
from email.header import decode_header

class EmailReader:
    def __init__(self, email_user: str, email_pass: str):
        self.email_user = email_user
        self.email_pass = email_pass
        self.mail = imaplib.IMAP4_SSL("imap.gmail.com")

    def login(self):
        self.mail.login(self.email_user, self.email_pass)

    def fetch_daily_emails(self) -> List[str]:
        self.mail.select("inbox")
        status, messages = self.mail.search(None, 'ALL')
        email_ids = messages[0].split()
        daily_emails = []

        for email_id in email_ids[-10:]:  # Fetch the last 10 emails
            res, msg = self.mail.fetch(email_id, "(RFC822)")
            msg = email.message_from_bytes(msg[0][1])
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding if encoding else 'utf-8')
            daily_emails.append(subject)

        return daily_emails

    def logout(self):
        self.mail.logout()

# Async wrapper for FastAPI endpoint usage
def fetch_daily_emails(current_user: str):
    # Dummy implementation for now, returns example emails
    # In production, use EmailReader and user credentials
    return [
        "Welcome to your inbox!",
        "Your daily summary",
        "Meeting at 3 PM",
        "Invoice attached"
    ]