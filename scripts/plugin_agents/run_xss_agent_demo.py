from s2nagent.plugin_agents.registry import get_plugin_agent


def main():
    agent = get_plugin_agent("xss")
    if agent is None:
        raise RuntimeError("xss agent not found in registry")

    decision = agent.evaluate_target(
        url="/search?q=test",
        dom='<input name="q" value="test">',
        sitemap_summary="search form reflects q parameter",
        response_snippet='<input name="q" value="test">',
    )

    print(decision.model_dump_json(indent=2))


if __name__ == "__main__":
    main()