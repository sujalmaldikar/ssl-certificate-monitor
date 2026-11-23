from email_notifier import send_alert_email

send_alert_email(
    certificate="example.test",
    expiry="2026-11-28 14:30:00 UTC",
    days_remaining=4,
    severity="WARNING"
)
