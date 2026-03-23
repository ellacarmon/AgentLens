from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Tuple

from ..models.schema import (
    Category,
    Finding,
    SemanticSampleItem,
    SemanticSampleSummary,
    Severity,
)
from ..analyzers.semantic import SemanticAnalyzer, SemanticDecision
from .scoring import ScoringEngine

if TYPE_CHECKING:
    from ..analyzers.injection_prefilter import PromptInjectionPrefilter

TRIGGER_CATEGORIES = {Category.CODE_EXECUTION, Category.NETWORK_ACCESS}

SEMANTIC_SAMPLE_SIZE = 3
"""Max findings sent to the Azure semantic LLM per scan."""

SEMANTIC_CANDIDATE_POOL_SIZE = 15
"""How many top static trigger findings to score with the injection classifier before picking the batch."""

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


def select_top_trigger_findings(
    findings: List[Finding], *, limit: int = SEMANTIC_SAMPLE_SIZE
) -> List[Finding]:
    """Return up to `limit` code_execution / network_access findings for the LLM.

    Selection policy (deterministic, no ML here):

    1. **Eligible** — only ``code_execution`` and ``network_access`` (same gate as before).

    2. **Sort** — descending by static ``severity`` (CRITICAL→LOW), then by
       ``confidence``. This is the primary "how dangerous" ordering.

    3. **De-duplicate by (rule_id, file_path)** — walk the sorted list and keep
       the first occurrence per pair. That instance is already the strongest hit
       for that rule in that file. This spreads samples across *files* and *rules*
       without letting thousands of identical repeats crowd out other locations.

    4. **Take the first ``limit`` representatives**. If there are fewer than
       ``limit`` unique pairs, **fill** from the full sorted list (next hits,
       including extra lines for the same rule/file) until ``limit`` or exhausted.

    Earlier we biased by "one finding per rule_id" globally, which could rank a
    lower-severity rule above a second CRITICAL hit for another file — this order
    fixes that.
    """
    trigger_findings = [f for f in findings if f.category in TRIGGER_CATEGORIES]
    if not trigger_findings:
        return []
    trigger_findings.sort(
        key=lambda f: (SEVERITY_RANK[f.severity], f.confidence), reverse=True
    )
    seen_pair: set[tuple[str, str]] = set()
    representatives: List[Finding] = []
    for f in trigger_findings:
        key = (f.rule_id, f.file_path)
        if key in seen_pair:
            continue
        seen_pair.add(key)
        representatives.append(f)

    picked = representatives[:limit]
    if len(picked) >= limit:
        return picked

    for f in trigger_findings:
        if len(picked) >= limit:
            break
        if f in picked:
            continue
        picked.append(f)
    return picked


def finding_text_for_injection_classifier(finding: Finding) -> str:
    """Text passed to the local injection model (description + evidence, truncated)."""
    parts = [finding.description or "", finding.evidence or ""]
    text = "\n".join(p for p in parts if p).strip()
    if not text:
        text = finding.file_path or " "
    return text[:4000]


def select_findings_for_semantic_llm(
    findings: List[Finding],
    *,
    prefilter: Optional["PromptInjectionPrefilter"] = None,
    sample_size: int = SEMANTIC_SAMPLE_SIZE,
    pool_size: int = SEMANTIC_CANDIDATE_POOL_SIZE,
) -> Tuple[List[Finding], List[Optional[float]], Optional[str]]:
    """Pick findings for the semantic LLM; optionally rank a larger pool by injection score.

    Without ``prefilter``, behavior matches the historical policy: top ``sample_size``
    trigger findings by static severity/confidence (pool size only affects work done).

    With ``prefilter``, up to ``pool_size`` trigger findings are scored locally; the
    highest attack-likelihood snippets win the ``sample_size`` slots (ties break on
    static severity, then confidence) so the cloud LLM focuses on the most ambiguous /
    adversarial-looking content.
    """
    pool = select_top_trigger_findings(findings, limit=pool_size)
    if not pool:
        return [], [], None

    model_id: Optional[str] = None
    if prefilter is None or len(pool) <= sample_size:
        chosen = pool[:sample_size]
        scores: List[Optional[float]] = [None] * len(chosen)
        return chosen, scores, model_id

    try:
        texts = [finding_text_for_injection_classifier(f) for f in pool]
        raw_scores = prefilter.score_texts(texts)
    except Exception as e:
        print(
            f"WARNING: Injection prefilter failed ({e}); using static order for semantic batch.",
            file=sys.stderr,
        )
        chosen = pool[:sample_size]
        return chosen, [None] * len(chosen), None

    model_id = getattr(prefilter, "model_id", None)
    paired = list(zip(pool, raw_scores))
    paired.sort(
        key=lambda p: (-p[1], SEVERITY_RANK[p[0].severity], p[0].confidence),
    )
    top = paired[:sample_size]
    return [p[0] for p in top], [p[1] for p in top], model_id


def build_semantic_sample_summary(
    trigger_findings: List[Finding],
    sample: List[Finding],
    *,
    candidate_pool_count: int = 0,
    prefilter_model: Optional[str] = None,
    injection_scores: Optional[List[Optional[float]]] = None,
) -> SemanticSampleSummary:
    """Counts eligible trigger findings vs. the batch sent to the semantic analyzer."""
    inj = injection_scores or [None] * len(sample)
    return SemanticSampleSummary(
        trigger_finding_count=len(trigger_findings),
        candidate_pool_count=candidate_pool_count,
        prefilter_model=prefilter_model,
        sent_finding_count=len(sample),
        sample_limit=SEMANTIC_SAMPLE_SIZE,
        unique_file_count=len({f.file_path for f in sample}),
        items=[
            SemanticSampleItem(
                file_path=f.file_path,
                line_number=f.line_number,
                rule_id=f.rule_id,
                severity=f.severity,
                category=f.category,
                injection_score=inj[i] if i < len(inj) else None,
            )
            for i, f in enumerate(sample)
        ],
    )


def select_primary_finding(findings: List[Finding]) -> Optional[Finding]:
    """Return the single highest-priority trigger-category finding, or None."""
    batch = select_top_trigger_findings(findings, limit=1)
    return batch[0] if batch else None


class HybridEngine:
    def __init__(
        self,
        semantic_analyzer: SemanticAnalyzer,
        injection_prefilter: Optional["PromptInjectionPrefilter"] = None,
    ):
        self.semantic_analyzer = semantic_analyzer
        self.injection_prefilter = injection_prefilter

    def run(
        self,
        findings: List[Finding],
        context: Dict,
        config_path: Optional[str] = None,
        policy_path: Optional[str] = None,
        debug_log: Optional[Callable[[str], None]] = None,
    ) -> Dict:
        # Step 1: Static scoring
        scoring_engine = ScoringEngine(config_path=config_path, policy_path=policy_path)
        result = scoring_engine.calculate(findings, context)

        # Step 2: Gate — if static decision is allow, skip LLM
        if result["decision"].lower() == "allow":
            return result

        # Step 3: Gate — if no trigger-category finding, skip LLM
        trigger_findings = [f for f in findings if f.category in TRIGGER_CATEGORIES]
        pool_for_count = select_top_trigger_findings(
            findings, limit=SEMANTIC_CANDIDATE_POOL_SIZE
        )
        semantic_sample, inj_scores, prefilter_model = select_findings_for_semantic_llm(
            findings,
            prefilter=self.injection_prefilter,
            sample_size=SEMANTIC_SAMPLE_SIZE,
            pool_size=SEMANTIC_CANDIDATE_POOL_SIZE,
        )
        if not semantic_sample:
            return result

        sample_summary = build_semantic_sample_summary(
            trigger_findings,
            semantic_sample,
            candidate_pool_count=len(pool_for_count),
            prefilter_model=prefilter_model,
            injection_scores=inj_scores,
        )

        if debug_log is not None:
            parts = []
            for f, s in zip(semantic_sample, inj_scores):
                extra = f" inj={s:.3f}" if s is not None else ""
                parts.append(
                    f"{f.file_path}:{f.line_number or '?'}"
                    f" rule={f.rule_id} sev={f.severity.value}{extra}"
                )
            debug_log(
                "semantic LLM sample: "
                f"{len(semantic_sample)} finding(s) → " + " | ".join(parts)
            )

        # Step 4: LLM semantic analysis (batched top patterns for cross-context intent)
        verdict = self.semantic_analyzer.analyze_snippets(semantic_sample)

        # Step 5: Handle None verdict (LLM failure)
        if verdict is None:
            print("WARNING: SemanticAnalyzer returned None; using static result.", file=sys.stderr)
            result["semantic_sample"] = sample_summary
            return result

        # Step 6: Apply override logic
        if (
            verdict.decision == SemanticDecision.ALLOW
            and verdict.confidence_score >= self.semantic_analyzer.confidence_threshold
        ):
            result["decision"] = "allow"
            result["recommendation"] = "Safe to install — initial risks were semantically cleared."
            result["explanation"] = (
                "[Semantic Override] " + verdict.explanation + " | " + result.get("explanation", "")
            )
        else:
            result["explanation"] = (
                "[Semantic Analysis] " + verdict.explanation + " | " + result.get("explanation", "")
            )

        # Step 7: Attach verdict and sample stats (eligible vs. sent, paths)
        result["semantic_verdict"] = verdict
        result["semantic_sample"] = sample_summary

        return result
