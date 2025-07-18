import os
from groq import Groq
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

def generate_reply(summary: str) -> str:
    """
    Generate a professional, polite, and concise reply email based on the summarized content of the received email.
    The reply should address any questions or requests, ask for clarification if needed, and end with 'Best regards' and a placeholder for the sender's name.
    """
    prompt = (
        "You are an expert email assistant. Based on the following summary of an email, write a professional, polite, and concise reply. "
        "If the summary includes a question or request, address it directly. If information is missing, politely ask for clarification. "
        "Sign off with 'Best regards' and a placeholder for the sender's name.\n\n"
        f"Email summary:\n\"\"\"\n{summary}\n\"\"\"\n\n"
        "Reply:"
    )
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return "[Error: GROQ_API_KEY not set in environment]"
    try:
        client = Groq(api_key=api_key)
        completion = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=512,
            top_p=1,
            stream=False,
            stop=None,
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        return f"[Error generating reply: {e}]"