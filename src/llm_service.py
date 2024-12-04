from gpt4all import GPT4All
from src.redis_cache import get_cached_data, cache_data

model = GPT4All("nous-hermes-2-mistral")

def classify_email(subject, sender):
    """Classify email using LLM."""
    cache_key = f"email:{subject}:{sender}"
    cached_result = get_cached_data(cache_key)
    if cached_result:
        return cached_result

    prompt = f"Classify: {subject} by {sender}. Options: Work, School, Shopping. Rank: Urgent, Important, Normal. Response needed: Yes/No."
    response = model.predict(prompt, max_tokens=50)
    cache_data(cache_key, response)
    return response
