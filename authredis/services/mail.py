from django.core.mail import send_mail
from smtplib import SMTPException


def send_mail_to_authenticate(subject, message, email_from, recipient_list):
    try:
        send_mail( subject, message, email_from, recipient_list )
    except SMTPException as e:
        raise Exception('There was an error sending an email: ', str(e))