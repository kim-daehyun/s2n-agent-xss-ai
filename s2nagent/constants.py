"""
S2N-Agent 전역 상수.

플러그인 목록, severity 등 여러 모듈에서 공유하는 값을 여기서 관리합니다.
"""

# S2N 플러그인 목록 (plan.md §2 기준, 12개)
PLUGINS: list[str] = [
    "xss", "sqlinjection", "oscommand", "csrf", "file_upload",
    "brute_force", "soft_brute_force", "jwt", "autobot",
    "path_traversal", "sensitive_files", "react2shell",
]

# multi_step planner용 — 스캔 완료 시 "stop" 반환 가능
PLUGINS_WITH_STOP: list[str] = PLUGINS + ["stop"]

# FalsePositiveTask 판정값
FP_VERDICTS: frozenset[str] = frozenset({"confirmed", "likely_false_positive"})

# finding severity 레벨
SEVERITIES: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
