from users.models import CustomUser, MailOtp

from django.core.mail import EmailMessage


def send_Otp(user_mail, generatedcode):
    user = CustomUser.objects.get(email=user_mail)
    new_mailotp = MailOtp.objects.create(
        user=user,
        code=generatedcode,
    )
    mail_subject = 'email confirmation'
    message = f'your email confirmation  code is :{generatedcode}'
    email = EmailMessage(
        mail_subject,
        message,
        to=[user_mail]
    )
    email.send()
    new_mailotp.save()

