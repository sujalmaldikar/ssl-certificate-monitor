import os
import smtplib

from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

smtp_server = os.getenv("SMTP_SERVER")
smtp_port = int(os.getenv("SMTP_PORT", "587"))

try:
    print("Connecting to Gmail SMTP server...")

    with smtplib.SMTP(smtp_server, smtp_port, timeout=30) as server:

       

        server.ehlo()
        print("SMTP connection successful!")

        server.starttls()
        server.ehlo()
        print("TLS encryption enabled successfully!")

        print("Attempting Gmail authentication...")

        server.login(
            os.getenv("SMTP_USERNAME"),
            os.getenv("SMTP_PASSWORD")
        )

        print("Gmail authentication successful!")

except Exception as error:
    print("SMTP test failed:", repr(error))