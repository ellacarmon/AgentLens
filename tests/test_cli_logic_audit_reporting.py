from agentlens.cli import (
    _logic_audit_caution_recommendation,
    _logic_audit_explanation,
    _logic_audit_recommendation,
    _risk_level_for_score,
)
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


def test_logic_audit_allow_with_incoherences_uses_cautionary_recommendation():
    logic_result = LogicAuditResult(
        risk_score=6,
        incoherences=["AI skill is missing a manifest file or the manifest could not be read."],
        dangerous_instructions=[],
        verdict=LogicAuditVerdict.ALLOW,
        rationale="Logic audit LLM returned no result; using heuristic contextual audit.",
    )

    explanation = _logic_audit_explanation(logic_result)
    recommendation = _logic_audit_caution_recommendation(logic_result)

    assert "appears safe" not in explanation.lower()
    assert "missing a manifest" in explanation
    assert recommendation.startswith("Install with caution")
    assert "should be reviewed" in recommendation


def test_risk_level_is_recomputed_from_final_score():
    assert _risk_level_for_score(3.99) == "LOW"
    assert _risk_level_for_score(4.0) == "MEDIUM"
    assert _risk_level_for_score(6.0) == "MEDIUM"
    assert _risk_level_for_score(7.0) == "HIGH"
    assert _risk_level_for_score(9.0) == "CRITICAL"
