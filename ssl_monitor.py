
import subprocess
import json
import math
import logging
import re

from datetime import datetime, timezone
from pathlib import Path

from email_notifier import send_alert_email


# ==========================================
# CONFIGURATION
# ==========================================

ALERT_THRESHOLD_DAYS = 5

BASE_DIR = Path(__file__).resolve().parent

TEST_CERTIFICATE_FOLDER = BASE_DIR / "test-certs"

CERTBOT_CONFIG_DIR = BASE_DIR / "certbot-data" / "config"
CERTBOT_LIVE_FOLDER = CERTBOT_CONFIG_DIR / "live"

REPORT_FOLDER = BASE_DIR / "reports"
LOG_FOLDER = BASE_DIR / "logs"

ALERT_HISTORY_FILE = BASE_DIR / "alert_history.json"


# ==========================================
# LOGGING CONFIGURATION
# ==========================================

LOG_FOLDER.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_FOLDER / "ssl_monitor.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


# ==========================================
# CERTIFICATE DISCOVERY
# ==========================================

def discover_certificates():
    """Discover test certificates and Certbot-managed certificates."""

    discovered = []

    # Discover test certificates
    for cert_path in TEST_CERTIFICATE_FOLDER.glob("*.crt"):

        discovered.append({
            "name": cert_path.stem,
            "path": cert_path,
            "source": "TEST"
        })

    # Discover Certbot certificates
    for cert_path in CERTBOT_LIVE_FOLDER.glob("*/cert.pem"):

        discovered.append({
            "name": cert_path.parent.name,
            "path": cert_path,
            "source": "CERTBOT"
        })

    discovered.sort(key=lambda item: item["name"])

    return discovered


# ==========================================
# CERTIFICATE EXPIRY EXTRACTION
# ==========================================

def get_certificate_expiry(cert_path):
    """Extract certificate expiry date using OpenSSL."""

    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-in", str(cert_path),
            "-noout",
            "-enddate"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    expiry_text = result.stdout.strip().split("=", 1)[1]

    expiry_date = datetime.strptime(
        expiry_text,
        "%b %d %H:%M:%S %Y %Z"
    ).replace(tzinfo=timezone.utc)

    return expiry_date


# ==========================================
# CERTIFICATE DOMAIN EXTRACTION
# ==========================================

def get_certificate_domains(cert_path):
    """Extract DNS domain names from SAN extension."""

    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-in", str(cert_path),
            "-noout",
            "-ext", "subjectAltName"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    domains = re.findall(
        r"DNS:([^,\s]+)",
        result.stdout
    )

    return domains


# ==========================================
# CERTIFICATE STATUS CHECK
# ==========================================

def check_certificate(cert_path, certificate_name):
    """Check certificate validity, domains and remaining days."""

    expiry_date = get_certificate_expiry(cert_path)

    domains = get_certificate_domains(cert_path)

    current_time = datetime.now(timezone.utc)

    remaining_seconds = (
        expiry_date - current_time
    ).total_seconds()

    if remaining_seconds <= 0:

        status = "EXPIRED"
        days_remaining = 0

    else:

        days_remaining = math.ceil(
            remaining_seconds / 86400
        )

        if days_remaining <= ALERT_THRESHOLD_DAYS:
            status = "WARNING"
        else:
            status = "VALID"

    return {
        "certificate": certificate_name,
        "domains": domains,
        "expiry": expiry_date.strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
        "days_remaining": days_remaining,
        "status": status
    }


# ==========================================
# ALERT HISTORY MANAGEMENT
# ==========================================

def load_alert_history():
    """Load previously sent alert records."""

    if not ALERT_HISTORY_FILE.exists():
        return {}

    try:

        return json.loads(
            ALERT_HISTORY_FILE.read_text(
                encoding="utf-8"
            )
        )

    except (json.JSONDecodeError, OSError) as error:

        logger.error(
            "Could not read alert history: %s",
            error
        )

        return {}


def save_alert_history(history):
    """Save alert history into JSON file."""

    ALERT_HISTORY_FILE.write_text(
        json.dumps(history, indent=4),
        encoding="utf-8"
    )


# ==========================================
# EMAIL ALERT MANAGEMENT
# ==========================================


def process_alert(result, alert_history):
    """Send one alert per certificate per day until renewal or expiry."""

    severity = (
        "CRITICAL"
        if result["status"] == "EXPIRED"
        else "WARNING"
    )

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    alert_key = (
        f"{result['certificate']}|"
        f"{result['expiry']}|"
        f"{today}"
    )

    if alert_key in alert_history:

        logger.info(
            "Daily duplicate alert skipped: %s",
            result["certificate"]
        )

        return "Duplicate skipped"

    logger.warning(
        "Certificate alert detected: %s | Severity: %s",
        result["certificate"],
        severity
    )

    email_sent = send_alert_email(
        certificate=result["certificate"],
        expiry=result["expiry"],
        days_remaining=result["days_remaining"],
        severity=severity,
        domains=result["domains"]
    )

    if email_sent:

        alert_history[alert_key] = {
            "certificate": result["certificate"],
            "domains": result["domains"],
            "expiry": result["expiry"],
            "status": result["status"],
            "severity": severity,
            "sent_at": datetime.now(
                timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        }

        save_alert_history(alert_history)

        logger.info(
            "Daily email notification successful: %s",
            result["certificate"]
        )

        return "Email sent"

    logger.error(
        "Email notification failed: %s",
        result["certificate"]
    )

    return "Email failed - retry next run"



# ==========================================
# MAIN MONITORING FUNCTION
# ==========================================

def generate_report():
    """Discover certificates, check expiry, send alerts and generate report."""

    REPORT_FOLDER.mkdir(parents=True, exist_ok=True)

    certificates = discover_certificates()

    test_count = sum(
        1 for cert in certificates
        if cert["source"] == "TEST"
    )

    certbot_count = sum(
        1 for cert in certificates
        if cert["source"] == "CERTBOT"
    )

    logger.info(
        "Total discovered: %d | Test: %d | Certbot: %d",
        len(certificates),
        test_count,
        certbot_count
    )

    if certbot_count == 0:
        logger.info("No Certbot-managed certificates found")

    if not certificates:
        logger.warning("No certificates found")

    alert_history = load_alert_history()

    report_lines = [
        "SSL CERTIFICATE MONITORING REPORT",
        "=" * 45,
        f"Generated at: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Alert threshold: {ALERT_THRESHOLD_DAYS} days",
        f"Total certificates discovered: {len(certificates)}",
        f"Test certificates: {test_count}",
        f"Certbot certificates: {certbot_count}",
        ""
    ]

    for certificate in certificates:

        cert_path = certificate["path"]
        certificate_name = certificate["name"]
        source = certificate["source"]

        try:

            result = check_certificate(
                cert_path,
                certificate_name
            )

            logger.info(
                "Certificate: %s | Source: %s | Domains: %s | Status: %s | Days remaining: %s",
                result["certificate"],
                source,
                ", ".join(result["domains"]) or "No SAN domains found",
                result["status"],
                result["days_remaining"]
            )

            email_status = "Not required"

            if result["status"] in ("WARNING", "EXPIRED"):

                email_status = process_alert(
                    result,
                    alert_history
                )

            report_lines.extend([
                "-" * 45,
                f"Certificate: {result['certificate']}",
                f"Source: {source}",
                f"Domains: {', '.join(result['domains']) or 'No SAN domains found'}",
                f"Expiry date: {result['expiry']}",
                f"Days remaining: {result['days_remaining']}",
                f"Status: {result['status']}",
                f"Email notification: {email_status}",
                ""
            ])

        except (
            subprocess.CalledProcessError,
            ValueError,
            OSError
        ):

            logger.exception(
                "Error checking certificate: %s",
                certificate_name
            )

            report_lines.extend([
                "-" * 45,
                f"Certificate: {certificate_name}",
                f"Source: {source}",
                "Status: ERROR",
                "Error: See monitoring log for details",
                ""
            ])

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    report_file = (
        REPORT_FOLDER /
        f"ssl_report_{timestamp}.txt"
    )

    report_content = "\n".join(report_lines)

    report_file.write_text(
        report_content,
        encoding="utf-8"
    )

    print("\n" + report_content)

    logger.info(
        "Report saved successfully: %s",
        report_file
    )


# ==========================================
# APPLICATION ENTRY POINT
# ==========================================

if __name__ == "__main__":

    logger.info("SSL Certificate Monitoring Started")

    try:

        generate_report()

    except Exception:

        logger.exception(
            "Unexpected monitoring failure"
        )

    finally:

        logger.info(
            "SSL Certificate Monitoring Completed"
        )
