from src.gmail_service import authenticate_gmail, get_emails
from src.llm_service import classify_email
from src.plot_utils import plot_email_categories
from src.redis_cache import cache_data

def main():
    # Authenticate and get Gmail service object
    service = authenticate_gmail()

    # Fetch emails
    email_data = get_emails(service, limit=100)

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
