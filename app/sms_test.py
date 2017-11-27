from twilio.rest import Client

# Your Account SID from twilio.com/console
account_sid = "AC5fbabd01858e9920b380f7e18630455e"
# Your Auth Token from twilio.com/console
auth_token  = "c5f1b4dcf588ec9be330ed408102d2e2"

client = Client(account_sid, auth_token)

message = client.messages.create(
    to="+16479793322",
    from_="12898001727",
    body="Hello from Python! Testing if the lib works")

print(message.sid)
