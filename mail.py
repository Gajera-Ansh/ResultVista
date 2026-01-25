from flask_mail import Mail, Message

mail = Mail()


def init_mail(app):
    # Initialize mail with Flask app

    mail.init_app(app)


def send_welcome_email(user_email, user_name):
    # Send welcome email after successful registration

    try:
        msg = Message(subject="Welcome to ResultVista 🎉", recipients=[user_email])
        msg.body = f"""
Hello {user_name},

Your account has been created successfully.

You can now log in and start using the website.

Regards,
Team
"""
        mail.send(msg)

    except Exception as e:
        print("Email sending failed:", e)
