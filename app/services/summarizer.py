from typing import List
from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv()

def summarize_email(content: str) -> str:
    """
    Use Groq LLM to generate a 2-3 line summary of the email content.
    """
    prompt = (
        "Summarize the following email in 2-3 clear, informative sentences so the reader understands the main points and context. "
        "Be concise but cover the important details.\n\n"
        f"Email:\n" + content
    )
    api_key = os.getenv("GROQ_API_KEY")
    try:
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=128,
            top_p=1,
            stream=False,
            stop=None,
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        return f"[Error generating summary: {e}]"

def summarize_emails(emails: List[str]) -> List[str]:
    return [summarize_email(email) for email in emails]