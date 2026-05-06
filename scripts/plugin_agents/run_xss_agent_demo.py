import json

from s2nagent.plugin_agents.registry import get_plugin_agent


def print_section(title: str, data):
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)

    if hasattr(data, "model_dump"):
        print(data.model_dump_json(indent=2))
    else:
        print(json.dumps(data, indent=2, ensure_ascii=False))


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

    print_section("1. XSSAgent decision", decision)

    fp_result = agent.filter_false_positive(
        finding="Possible reflected XSS",
        evidence="<svg/onload=alert(1)>",
        response_body="Search results: <svg/onload=alert(1)>",
    )

    print_section("2. False positive filter result", fp_result)

    next_action = agent.plan_next_action(
        completed=["xss"],
        findings=[
            {
                "plugin": "xss",
                "severity": "HIGH",
                "title": "Reflected XSS",
            }
        ],
        sitemap="state-changing forms and admin route discovered",
    )

    print_section("3. Next action plan", next_action)


if __name__ == "__main__":
    main()