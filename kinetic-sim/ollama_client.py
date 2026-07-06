"""
ollama_client.py — Retry-safe Ollama wrapper for qwen2.5:0.5b.

RTX 2050 has 4GB VRAM. qwen2.5:0.5b sits in ~400MB leaving 3.6GB free.
Semaphore cap of 2 concurrent calls prevents VRAM thrashing.
All calls use structured JSON mode and validate the output before returning.
"""

import json
import threading
import time
import requests

OLLAMA_URL  = "http://localhost:11434/api/chat"
MODEL       = "qwen2.5:3b"

MAX_RETRIES = 3
TIMEOUT     = 45          # seconds per call
_semaphore  = threading.Semaphore(2)  # max 2 concurrent GPU calls


def query(system_prompt: str, user_prompt: str, required_keys: list[str] = None) -> dict | None:
    """
    Call Ollama with JSON mode.  Returns a parsed dict if valid, None on total failure.
    Retries up to MAX_RETRIES times with exponential backoff.
    Validates that 'required_keys' are present in the response if provided.
    """
    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "format": "json",
        "stream": False,
        "options": {
            "temperature": 0.7,
            "num_predict": 120,   # short narrative only — we don't need essays
        },
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with _semaphore:
                resp = requests.post(OLLAMA_URL, json=payload, timeout=TIMEOUT)
                resp.raise_for_status()
                raw = resp.json()["message"]["content"]
                data = json.loads(raw)

                if required_keys:
                    if not all(k in data for k in required_keys):
                        raise ValueError(f"Missing keys {required_keys} in {data}")

                return data

        except json.JSONDecodeError as e:
            # Model produced malformed JSON — try a tighter prompt
            payload["messages"][-1]["content"] = (
                user_prompt + " IMPORTANT: output ONLY valid JSON, nothing else."
            )
            _backoff(attempt)

        except requests.exceptions.Timeout:
            _backoff(attempt)

        except Exception as e:
            print(f"[Ollama] Attempt {attempt}/{MAX_RETRIES} failed: {e}", flush=True)
            _backoff(attempt)

    return None


def _backoff(attempt: int):
    wait = 2 ** attempt
    time.sleep(wait)
