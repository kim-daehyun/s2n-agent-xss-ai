import json

from s2n_ai.fastapi_client import call_xss_agent
from s2n_ai.finding_normalizer import normalize_xss_finding


def main():
    request_payload = {
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

    print("[1] Calling FastAPI XSSAgent...")
    agent_response = call_xss_agent(request_payload)

    raw_finding = {
        "url": request_payload["url"],
        "method": request_payload["method"],
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "reflection": True,
        "reflected_value": "<script>alert(1)</script>",
        "response_snippet": "<p>You searched for: <script>alert(1)</script></p>",
        "severity": "medium",
    }

    print("[2] Normalizing finding...")
    normalized = normalize_xss_finding(raw_finding, agent_response)

    print(json.dumps(normalized, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
