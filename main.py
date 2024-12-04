from __future__ import print_function
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

# Scope: grants read-only access to Gmail
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# Your email address
USER_EMAIL = "danielmass.cs@gmail.com"

def authenticate_gmail():
    """Authenticate with Gmail API using credentials.json."""
    creds = None

    # Check if token.json exists (for reusing credentials)
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # If there are no valid credentials, authenticate again
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Load credentials.json for the first-time authentication
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next time
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def get_emails(service):
    """Fetch email subjects and senders."""
    results = service.users().messages().list(userId=USER_EMAIL, maxResults=5).execute()
    messages = results.get('messages', [])
    
    if not messages:
        print('No messages found.')
    else:
        print('Messages:')
        for message in messages:
            msg = service.users().messages().get(userId=USER_EMAIL, id=message['id']).execute()
            headers = msg['payload']['headers']
            
            # Extract the subject and sender
            subject = next((header['value'] for header in headers if header['name'] == 'Subject'), "No Subject")
            sender = next((header['value'] for header in headers if header['name'] == 'From'), "Unknown Sender")
            
            print(f"Subject: {subject}\nFrom: {sender}\n")

if __name__ == '__main__':
    # Authenticate and get Gmail service object
    service = authenticate_gmail()
    get_emails(service)