from agentlens.cli import _logic_audit_explanation, _logic_audit_recommendation
from agentlens.models.schema import LogicAuditResult, LogicAuditVerdict


def test_logic_audit_block_explanation_owns_message():
    logic_result = LogicAuditResult(
        risk_score=9,
        incoherences=[
            "Manifest/instructions explicitly deny network access or external dependencies, but the skill documentation describes live network/tool activity.",
            "Skill documentation grants cross-skill authority such as reading, benchmarking, activating, or modifying other installed skills.",
        ],
        dangerous_instructions=[],
        verdict=LogicAuditVerdict.BLOCK,
        rationale="Using heuristic contextual audit.",
    )

    explanation = _logic_audit_explanation(logic_result)
    recommendation = _logic_audit_recommendation(logic_result)

    assert "Logic Audit" in explanation
    assert "appears safe" not in explanation.lower()
    assert "deny network access" in explanation
    assert recommendation.startswith("Block pending manual review")
    assert "material contradictions" in recommendation
