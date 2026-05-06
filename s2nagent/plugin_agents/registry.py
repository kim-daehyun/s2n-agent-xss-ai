from s2nagent.plugin_agents.xss import XSSAgent


PLUGIN_AGENT_REGISTRY = {
    "xss": {
        "agent_id": "xss_agent",
        "plugin": "xss",
        "class": XSSAgent,
        "model": "s2n-agent-xss",
        "fallback_model": "s2n-agent",
        "adapter": "lora-out/xss",
        "priority": "P0",
        "tasks": [
            "selection",
            "payload_planning",
            "false_positive",
            "multi_step",
        ],
    }
}


def get_plugin_agent(plugin: str):
    item = PLUGIN_AGENT_REGISTRY.get(plugin)
    if not item:
        return None
    return item["class"]()


def list_plugin_agents():
    return PLUGIN_AGENT_REGISTRY