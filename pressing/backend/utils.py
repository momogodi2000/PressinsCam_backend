# utils.py
import os
from twilio.rest import Client
from django.conf import settings

def send_otp_via_sms(phone_number, otp_code):
    """
    Send OTP code via SMS using Twilio
    """
    try:
        # Your Twilio credentials
        account_sid = settings.TWILIO_ACCOUNT_SID
        auth_token = settings.TWILIO_AUTH_TOKEN
        from_number = settings.TWILIO_PHONE_NUMBER
        
        client = Client(account_sid, auth_token)
        
        message = client.messages.create(
            body=f"Your verification code is: {otp_code}",
            from_=from_number,
            to=phone_number
        )
        
        return True, message.sid
    except Exception as e:
        return False, str(e)
    
