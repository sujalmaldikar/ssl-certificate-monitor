# Automated SSL Certificate Expiry Monitoring System

A Python-based DevOps automation project that monitors SSL/TLS certificates, detects upcoming expirations, generates monitoring reports, and sends email alerts automatically.

## Project Overview

SSL/TLS certificates secure communication between clients and servers. Expired certificates can cause browser security warnings, application downtime, and service disruptions.

This project automates certificate monitoring by discovering certificates, checking their expiration dates, and sending email notifications before they expire.

## Features

- Automatic discovery of test certificates and Certbot-managed certificates.
- Extracts certificate expiry dates using OpenSSL.
- Extracts domain names from Subject Alternative Name (SAN).
- Detects expired and expiring certificates.
- Sends email alerts using Gmail SMTP.
- Prevents duplicate email notifications using alert history.
- Generates timestamped monitoring reports.
- Maintains application logs.
- Supports daily automated execution using Cron.
- Uses environment variables to protect SMTP credentials.

## Technologies Used

- **Python:** Monitoring automation
- **OpenSSL:** Certificate inspection
- **Certbot:** SSL certificate management
- **Gmail SMTP:** Email notifications
- **Cron:** Scheduled execution
- **Git & GitHub:** Version control
- **python-dotenv:** Environment configuration
- **cryptography:** Test certificate generation

## Project Structure

```text
ssl-certificate-monitor/
│
├── ssl_monitor.py
├── email_notifier.py
├── generate_expired_cert.py
├── send_test_alert.py
├── test_email.py
├── requirements.txt
├── .gitignore
├── README.md
│
├── reports/
├── logs/
├── test-certs/
├── certbot-data/
├── alert_history.json
└── .env
```

Runtime folders and sensitive files are excluded from Git using `.gitignore`.

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/sujalmaldikar/ssl-certificate-monitor.git

cd ssl-certificate-monitor
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Create a `.env` file in the project root:

```env
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_gmail_app_password
EMAIL_RECIPIENT=recipient@gmail.com
```

Use a Gmail App Password rather than your normal Gmail password.

Never upload `.env` to GitHub.

## Running the Monitoring System

Run:

```bash
python ssl_monitor.py
```

The script will:

1. Discover available certificates.
2. Extract certificate expiry dates.
3. Identify covered domains.
4. Calculate remaining validity.
5. Classify certificate status.
6. Send email alerts when required.
7. Generate a monitoring report.
8. Save execution logs.

## Alert Configuration

The default alert threshold is **5 days**.

- **VALID:** More than 5 days remaining — no alert.
- **WARNING:** 5 days or fewer remaining — send warning email.
- **EXPIRED:** Certificate has expired — send critical email.

Duplicate notifications are prevented using `alert_history.json`.

## Automated Scheduling Using Cron

The project can run automatically every day at 9:00 AM.

Example Cron configuration:

```cron
0 9 * * * cd /path/to/ssl-certificate-monitor && /path/to/ssl-certificate-monitor/venv/bin/python ssl_monitor.py >> /path/to/ssl-certificate-monitor/logs/cron.log 2>&1
```

Replace the paths with the actual project and virtual environment paths on your server.

## Testing

Test certificates can be generated with different validity periods to verify monitoring behavior.

The project includes a Python script for generating an expired test certificate:

```bash
python generate_expired_cert.py
```

Run the monitoring system afterward:

```bash
python ssl_monitor.py
```

Test scenarios include:

- Valid certificates.
- Certificates expiring within 5 days.
- Expired certificates.
- Certificates containing multiple SAN domains.
- Duplicate alert prevention.

## Certbot Integration

The monitoring system supports discovering Certbot-managed certificates from its configured directory.

For a Linux production environment, Certbot commonly stores certificates under:

```text
/etc/letsencrypt/
├── live/
├── archive/
└── renewal/
```

The monitoring configuration should point to the appropriate Certbot directory on the target server.

## Future Improvements

- Deploy monitoring on a Linux server.
- Add systemd timer support.
- Integrate Slack or Microsoft Teams notifications.
- Add monitoring dashboards.
- Support multiple SMTP providers.
- Improve alert recovery and renewal tracking.

## Author

**Sujal Maldikar**

GitHub: https://github.com/sujalmaldikar

Project: https://github.com/sujalmaldikar/ssl-certificate-monitor

