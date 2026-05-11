import os
import requests


XSS_AGENT_API_URL = os.getenv(
    "XSS_AGENT_API_URL",
    "http://127.0.0.1:8000/predict/xss",
)


def call_xss_agent(payload: dict) -> dict:
    response = requests.post(
        XSS_AGENT_API_URL,
        json=payload,
        timeout=180,
    )
    response.raise_for_status()
    return response.json()


if __name__ == "__main__":
    sample = {
        "task": "selection",
        "url": "http://127.0.0.1:5000/search?q=test",
        "method": "GET",
        "parameters": ["q"],
        "response_sample": "<html><body><p>You searched for: test</p></body></html>",
        "evidence": {
            "reflection": True,
            "reflected_params": ["q"],
        },
    }

    print(call_xss_agent(sample))
