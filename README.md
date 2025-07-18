# FastAPI Email Agent

This project is a web application built using FastAPI that functions as an email agent. It is capable of reading daily emails, summarizing their content, and auto-generating reply emails. Users can sign in using their email ID to access the application's features.

## Project Structure

```
fastapi-email-agent
├── app
│   ├── main.py               # Entry point of the FastAPI application
│   ├── api
│   │   └── endpoints.py      # API endpoints for user authentication and email handling
│   ├── core
│   │   └── auth.py           # User authentication functions
│   ├── models
│   │   └── user.py           # User data model
│   ├── services
│   │   ├── email_reader.py    # Functions for reading emails
│   │   ├── summarizer.py      # Functions for summarizing email content
│   │   └── reply_generator.py  # Functions for generating reply emails
│   └── templates
│       └── index.html        # HTML template for the user interface
├── requirements.txt           # Project dependencies
├── README.md                  # Project documentation
└── .gitignore                 # Files and directories to ignore in version control
```

## Setup Instructions

1. **Clone the repository:**
   ```
   git clone <repository-url>
   cd fastapi-email-agent
   ```

2. **Create a virtual environment:**
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the required dependencies:**
   ```
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```
   uvicorn app.main:app --reload
   ```

5. **Access the application:**
   Open your web browser and navigate to `http://127.0.0.1:8000`.

## Usage Guidelines

- Sign in with your email ID to start using the email agent.
- The application will fetch your daily emails, summarize their content, and allow you to send replies based on the summaries.
- Explore the API endpoints for programmatic access to the application's features.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for more details.