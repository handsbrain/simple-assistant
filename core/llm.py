# core/llm.py
from __future__ import annotations
import os

def ask_chatgpt(prompt: str) -> str:
    if not prompt.strip():
        return "I received an empty message."
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
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as e:
        return f"(Error calling model: {type(e).__name__}: {e})"
