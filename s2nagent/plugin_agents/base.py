from __future__ import annotations

from typing import Any, Protocol

from s2nagent.plugin_agents.schemas import PluginAgentDecision


class PluginAgent(Protocol):
    """
    Minimal interface for plugin-specific agents.

    Each plugin agent is responsible for:
    - pre-scan decision
    - payload or test planning
    - false positive filtering
    - next action planning

    Implementors must expose agent_id, plugin, model as properties
    and implement evaluate_target with at minimum url and dom.
    Additional keyword arguments are forwarded to task-specific logic.
    """

    @property
    def agent_id(self) -> str: ...

    @property
    def plugin(self) -> str: ...

    @property
    def model(self) -> str: ...

    def evaluate_target(
        self,
        *,
        url: str,
        dom: str = "",
        **kwargs: Any,
    ) -> PluginAgentDecision: ...
