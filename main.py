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

    prompt = (
        f"Classify the following email: Subject: {subject}, Sender: {sender}. "
        "Analyze: Category (Work, School, Shopping), Urgency (Urgent, Important, Normal), Response needed (Yes/No). "
        "Provide the analysis in a structured format: 'Category, Urgency, Response'."
    )
    
    response = model.generate(prompt, max_tokens=75)
    response_text = response.strip()

    # Validate the response format
    if len(response_text.split(",")) < 3:
        # Return default values if the response is not in the expected format
        return "Unknown, Normal, No"
    
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


def classify_email(subject, sender):
    """Classify email using LLM."""
    cache_key = f"email:{subject}:{sender}"
    cached_result = get_cached_data(cache_key)
    if cached_result:
        return cached_result

    prompt = (
        f"Classify the following email: Subject: {subject}, Sender: {sender}. "
        "Analyze: Category (Work, School, Shopping), Urgency (Urgent, Important, Normal), Response needed (Yes/No). "
        "Provide the analysis in a structured format: 'Category, Urgency, Response'."
    )
    
    response = model.generate(prompt, max_tokens=50)
    response_text = response.strip()
    print(f"GPT Response: {response_text}")  # Debugging output

    # Validate the response format
    if len(response_text.split(",")) < 3:
        # Return default values if the response is not in the expected format
        return "Unknown, Normal, No"
    
    # Cache the response
    cache_data(cache_key, response_text)
    return response_text

def plot_email_categories(email_data):
    """Plot email categories: sender distribution and subject length distribution."""
    # Update font settings to avoid missing glyphs
    plt.rcParams['font.sans-serif'] = ['Arial']
    plt.rcParams['axes.unicode_minus'] = False

    # Count occurrences of each sender
    sender_counts = {}
    subject_length_counts = {"Short": 0, "Medium": 0, "Long": 0}

    for email in email_data:
        # Count senders
        sender = email['sender']
        sender_counts[sender] = sender_counts.get(sender, 0) + 1

        # Count subject length
        subject_length = len(email['subject'])
        if subject_length <= 30:
            subject_length_counts["Short"] += 1
        elif 31 <= subject_length <= 60:
            subject_length_counts["Medium"] += 1
        else:
            subject_length_counts["Long"] += 1

    # Simplify sender names and counts
    sender_names = list(sender_counts.keys())
    sender_values = list(sender_counts.values())

    # Subject length distribution
    subject_length_names = list(subject_length_counts.keys())
    subject_length_values = list(subject_length_counts.values())

    # Create first pie chart: Sender distribution
    plt.figure(figsize=(6, 6))
    plt.pie(sender_values, labels=sender_names, autopct='%1.1f%%', startangle=140)
    plt.title("Email Sender Distribution")
    plt.show()

    # Create second pie chart: Subject Length Distribution
    plt.figure(figsize=(6, 6))
    plt.pie(subject_length_values, labels=subject_length_names, autopct='%1.1f%%', startangle=140)
    plt.title("Subject Length Distribution")
    plt.show()

def main():
    # Authenticate and get Gmail service object
    service = authenticate_gmail()

    # Fetch emails
    email_data = get_emails(service, limit=15)

    # Classify emails using LLM
    classified_emails = []
    allowed_categories = ["Work", "Shopping", "Social", "Personal"]  # Allowed categories
    for email in email_data:
        subject = email['subject']
        sender = email['sender']
        try:
            classification = classify_email(subject, sender)
            classification_parts = classification.split(",")
            category = classification_parts[0].strip() if len(classification_parts) > 0 else "Unknown"
            urgency = classification_parts[1].strip() if len(classification_parts) > 1 else "Normal"
            response_needed = classification_parts[2].strip() if len(classification_parts) > 2 else "No"
        except Exception as e:
            # Handle unexpected errors during classification
            print(f"Error classifying email: {subject}. Error: {e}")
            category, urgency, response_needed = "Unknown", "Normal", "No"

        # Ensure category is one of the allowed ones
        if category not in allowed_categories:
            category = "Personal"

        # Add the classification results to the email dictionary
        email['category'] = category
        email['urgency'] = urgency
        email['response_needed'] = response_needed
        email['classification'] = f"{category}, {urgency}, {response_needed}"
        classified_emails.append(email)

        # Print email details to console
        print("-" * 40)
        print(f"Subject: {subject}")
        print(f"Sender: {sender}")
        print(f"Category: {category}")
        print(f"Urgency: {urgency}")
        print(f"Response Needed: {response_needed}")
        print("-" * 40)

    # Plot results
    plot_email_categories(classified_emails)


if __name__ == '__main__':
    main()
