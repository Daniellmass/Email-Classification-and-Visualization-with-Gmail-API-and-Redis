# Email Classification and Visualization with Gmail API and Redis

This Python project connects to Gmail, fetches email data, classifies the emails using GPT4All, caches results in Redis, and visualizes the email distribution with Matplotlib.

## Features
- **Gmail API Integration**: Authenticate and fetch email subjects and senders.
- **Email Classification**: Classify emails into categories (`Work`, `Shopping`, `Social`, `Personal`), determine urgency, and check if a response is needed using GPT4All.
- **Caching**: Use Redis to cache classification results to optimize performance.
- **Visualization**: Plot email distribution by sender and subject length with pie charts.

## Requirements
- Python 3.7+
- The following libraries are required:
  - `google-auth`
  - `google-auth-oauthlib`
  - `google-api-python-client`
  - `redis`
  - `gpt4all`
  - `matplotlib`

Install dependencies using:
```bash
pip install -r requirements.txt
