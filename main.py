import os
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from gpt4all import GPT4All
import redis
import json
import matplotlib.pyplot as plt

# Gmail Authentication
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate_gmail():
    """Authenticate with Gmail API using credentials.json located in the root directory."""
    creds = None

    # Get the absolute path of the current script (gmail_service.py)
    current_script_path = os.path.abspath(__file__)

    # Get the directory of the current script and join it with the filename of the credentials file
    credentials_path = os.path.join(os.path.dirname(current_script_path), '..', 'credentials.json')

    # Check if token.json exists (for reusing credentials)
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # If no valid credentials, authenticate again
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Load credentials.json from the root directory
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)

        # Save the credentials for the next time
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    return build('gmail', 'v1', credentials=creds)

def get_emails(service, limit=5):
    """Fetch email subjects and senders."""
    results = service.users().messages().list(userId='me', maxResults=limit).execute()
    messages = results.get('messages', [])
    email_data = []

    for message in messages:
        msg = service.users().messages().get(userId='me', id=message['id']).execute()
        headers = msg['payload']['headers']
        subject = next((header['value'] for header in headers if header['name'] == 'Subject'), "No Subject")
        sender = next((header['value'] for header in headers if header['name'] == 'From'), "Unknown Sender")
        email_data.append({'subject': subject, 'sender': sender})
    
    return email_data


# GPT4All Integration
model = GPT4All("Meta-Llama-3-8B-Instruct.Q4_0") 

def classify_email(subject, sender):
    """Classify email using LLM."""
    cache_key = f"email:{subject}:{sender}"
    cached_result = get_cached_data(cache_key)
    if cached_result:
        return cached_result

    prompt = f"Classify: {subject} by {sender}. Options: Work, School, Shopping. Rank: Urgent, Important, Normal. Response needed: Yes/No."
    
    # Use the generate method correctly
    response = model.generate(prompt, max_tokens=15)  # Generate text
    response_text = response.strip()  # Clean up any extra whitespace
    
    # Cache the response
    cache_data(cache_key, response_text)
    return response_text


# Redis Cache Functions
redis_client = redis.StrictRedis(host='localhost', port=6379, decode_responses=True)

def cache_data(key, value, expiry=14400):
    """Cache data in Redis."""
    redis_client.set(key, json.dumps(value))
    redis_client.expire(key, expiry)

def get_cached_data(key):
    """Retrieve cached data."""
    data = redis_client.get(key)
    return json.loads(data) if data else None


# Email Category Plotting
def plot_email_categories(email_data):
    categories = {}
    for email in email_data:
        category = email['classification'].split(",")[0].strip()
        categories[category] = categories.get(category, 0) + 1
    plt.figure(figsize=(8, 6))
    plt.pie(categories.values(), labels=categories.keys(), autopct='%1.1f%%')
    plt.title("Email Categories")
    plt.show()


# Main Function to run the process
def main():
    # Authenticate and get Gmail service object
    service = authenticate_gmail()

    # Fetch emails
    email_data = get_emails(service, limit=15)

    # Classify emails using LLM
    classified_emails = []
    for email in email_data:
        subject = email['subject']
        sender = email['sender']
        classification = classify_email(subject, sender)
        email['classification'] = classification
        classified_emails.append(email)

    # Plot results
    plot_email_categories(classified_emails)

if __name__ == '__main__':
    main()
