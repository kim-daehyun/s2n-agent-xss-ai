from __future__ import annotations

from typing import Protocol

from s2nagent.plugin_agents.schemas import PluginAgentDecision


class PluginAgent(Protocol):
    """
    Minimal interface for plugin-specific agents.

    Each plugin agent is responsible for:
    - pre-scan decision
    - payload or test planning
    - false positive filtering
    - next action planning
    """

    agent_id: str
    plugin: str
    model: str

    def evaluate_target(self, **kwargs) -> PluginAgentDecision:
        ...