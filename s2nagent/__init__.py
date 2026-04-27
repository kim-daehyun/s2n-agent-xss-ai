"""
S2N-Agent: LLM-powered decision layer for the S2N web vulnerability scanner.

Modes:
  off        — vanilla S2N (no AI)
  assist     — AI recommends plugins, human confirms
  smart      — AI selects plugins autonomously
  aggressive — AI plans multi-step attack chains
"""

__version__ = "0.1.0"


def __getattr__(name: str):
    if name == "S2NAgent":
        from s2nagent.agent import S2NAgent
        return S2NAgent
    raise AttributeError(f"module 's2nagent' has no attribute {name!r}")


__all__ = ["S2NAgent"]
