# core/llm.py
from __future__ import annotations
import os
import time
from typing import Optional

def ask_chatgpt(prompt: str, max_retries: int = 3) -> str:
    if not prompt.strip():
        return "I received an empty message."
    
    # Validate prompt length
    if len(prompt) > 100000:  # Reasonable limit
        return "Error: Prompt too long (max 100000 characters)"
    
    last_exception = None
    
    for attempt in range(max_retries + 1):
        try:
            from openai import OpenAI
            client = OpenAI(
                api_key=os.getenv("OPENAI_API_KEY"),
                base_url=os.getenv("OPENAI_BASE_URL") or None,   # usually empty
                organization=os.getenv("OPENAI_ORG") or None,    # optional
                project=os.getenv("OPENAI_PROJECT") or None,      # optional; fine for sk-proj- keys
            )
            model = os.getenv("OPENAI_MODEL", "gpt-5")
            
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a helpful professional assistant."},
                    {"role": "user", "content": prompt},
                ],
                max_completion_tokens=4000,  # Reasonable limit for responses
                temperature=0.7,
            )
            
            content = resp.choices[0].message.content or ""
            return content.strip()
            
        except Exception as e:
            last_exception = e
            
            # Handle rate limiting
            if "rate_limit" in str(e).lower() or "429" in str(e):
                if attempt < max_retries:
                    delay = 60 * (2 ** attempt)  # Exponential backoff for rate limits
                    print(f"Rate limited, waiting {delay}s before retry {attempt + 1}/{max_retries}")
                    time.sleep(delay)
                    continue
            
            # Handle other retryable errors
            if attempt < max_retries and any(keyword in str(e).lower() for keyword in ["timeout", "connection", "server"]):
                delay = 2 ** attempt  # Exponential backoff
                print(f"API error, retrying in {delay}s (attempt {attempt + 1}/{max_retries}): {type(e).__name__}")
                time.sleep(delay)
                continue
            
            # Don't retry on other errors
            break
    
    return f"(Error calling model: {type(last_exception).__name__}: {last_exception})"
