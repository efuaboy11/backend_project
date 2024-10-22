import smtplib
from email.mime.text import MIMEText
from django.conf import settings

def send_email(to_email, message, subject):
    msg = MIMEText(message, 'html') 
    msg['Subject'] = f'{subject}'
    msg['From'] = settings.DEFAULT_FROM_EMAIL
    msg['To'] = to_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
            server.send_message(msg)
        print("email sent successfully.")
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False
