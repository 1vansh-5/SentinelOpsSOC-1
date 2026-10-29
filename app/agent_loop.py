
"""Bounded Gemini-guided investigation loop with provenance reporting."""

from .evidence_tools import ALLOWED_TOOLS, retrieve_evidence
from .gemini_planner import choose_next_tool
from .evidence_provenance import validate_evidence_provenance
from .gemini_runtime import workflow_budget


@workflow_budget()
def run_investigation(
    alert: dict,
    max_steps: int = 4,
    scenario: str | None = None,
) -> dict:
    """Collect evidence and report its trust status."""

    if (
        type(max_steps) is not int
        or not 1 <= max_steps <= 4
    ):
        raise ValueError("max_steps must be between 1 and 4")

    trace = []

    for _ in range(max_steps):
        decision = choose_next_tool(alert, trace)
        tool_name = decision.get("tool")

        used_tools = {
            step["tool"] for step in trace
        }

        if tool_name is None:
            break

        if (
            tool_name not in ALLOWED_TOOLS
            or tool_name in used_tools
        ):
            break

        result = retrieve_evidence(
            tool_name,
            alert,
            scenario=scenario,
        )

        trace.append({
            "step": len(trace) + 1,
            "tool": tool_name,
            "planner_status": decision["planner_status"],
            "reason": decision["reason"],
            "ai_status": decision.get('ai_status','fallback_rules'),
            "reasoning_source": decision.get('reasoning_source','fallback_rules'),
            "fallback_reason": decision.get('fallback_reason'),
            "evidence_refs": decision.get('evidence_refs',[]),
            "ai_metadata": decision.get('ai_metadata',{}),
            "result": result,
        })

    investigation = {
        "investigation_status": "completed",
        "steps_taken": len(trace),
        "trace": trace,
        "conclusion": "INCONCLUSIVE",
        "note": (
            "Evidence collection finished. "
            "Independent outcome assessment is still required."
        ),
    }

    provenance = validate_evidence_provenance({
        "investigation": investigation
    })

    investigation["provenance"] = provenance
    investigation["evidence_trusted"] = provenance["trusted"]
    investigation['reasoning_sources'] = sorted({step['reasoning_source'] for step in trace})

    return investigation
