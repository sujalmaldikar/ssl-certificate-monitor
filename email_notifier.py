
import os
import smtplib
import socket

from email.message import EmailMessage
from dotenv import load_dotenv
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# Load SMTP configuration from .env
load_dotenv(BASE_DIR / ".env")


def send_alert_email(certificate, expiry, days_remaining, severity, domains=None):
    """Send SSL certificate expiry notification."""

    smtp_server = os.getenv("SMTP_SERVER")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    recipient = os.getenv("EMAIL_RECIPIENT")

    # Validate required configuration
    if not all([smtp_server, smtp_username, smtp_password, recipient]):
        print("Email configuration is incomplete.")
        return False

    message = EmailMessage()

    message["Subject"] = f"{severity}: SSL Certificate Expiry Alert"
    message["From"] = smtp_username
    message["To"] = recipient

    hostname = socket.gethostname()

    domain_list = (
        "\n".join(f"- {domain}" for domain in domains)
        if domains
        else "No SAN domains found"
    )

    message.set_content(f"""
SSL CERTIFICATE EXPIRY ALERT

Server: {hostname}

Certificate: {certificate}

Covered Domains:
{domain_list}

Expiry Date: {expiry}

Days Remaining: {days_remaining}

Severity: {severity}

Please take the necessary action to renew this certificate.

Regards,
SSL Certificate Monitoring System
""")

    try:
        with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as server:
            server.starttls()
            server.login(smtp_username, smtp_password)
            server.send_message(message)

        print(f"Alert email sent for {certificate}")
        return True

    except (smtplib.SMTPException, OSError) as error:
        print(f"Failed to send email: {error}")
        return False
