from typing import List, Dict, Tuple
from ..models.schema import Finding, Category, Severity

class ScoringEngine:
    def __init__(self):
        self.severity_weights = {
            Severity.LOW: 1.0,
            Severity.MEDIUM: 2.0,
            Severity.HIGH: 4.0,
            Severity.CRITICAL: 6.0
        }
        self.decay_factor = 0.3
        
    def calculate(self, findings: List[Finding]) -> Tuple[float, float, Dict[str, float], Dict[str, float], List[Finding]]:
        categories_breakdown: Dict[str, float] = {
            Category.CODE_EXECUTION.value: 0.0,
            Category.PROMPT_INJECTION.value: 0.0,
            Category.NETWORK_ACCESS.value: 0.0,
            Category.SUPPLY_CHAIN.value: 0.0,
            Category.FILESYSTEM_ACCESS.value: 0.0
        }
        
        # Group findings by category
        grouped_findings: Dict[Category, List[Finding]] = {cat: [] for cat in Category}
        for finding in findings:
            grouped_findings[finding.category].append(finding)
            
        # Step 1: Diminishing Returns per Category
        for cat, cats_findings in grouped_findings.items():
            # Sort findings by severity descending
            cats_findings.sort(key=lambda f: self.severity_weights.get(f.severity, 0.0), reverse=True)
            
            score_c = 0.0
            for i, f in enumerate(cats_findings):
                weight = self.severity_weights.get(f.severity, 0.0)
                score_c += weight * (self.decay_factor ** i)
                
            categories_breakdown[cat.value] = min(10.0, score_c)
            
        # Step 2: Probabilistic OR Aggregation
        p_safe = 1.0
        for score_c in categories_breakdown.values():
            p_safe *= (1.0 - (score_c / 10.0))
            
        risk_score = 10.0 * (1.0 - p_safe)
        risk_score = round(risk_score, 2)
        
        # Calculate Confidence
        confidence = 1.0
        if findings:
            # Default precision estimation
            confidence = 0.9 
            
        # Calculate Normalized Contributions
        normalized_contributions: Dict[str, float] = {}
        total_category_score = sum(categories_breakdown.values())
        if total_category_score > 0:
            for cat, score in categories_breakdown.items():
                if score > 0:
                    normalized_contributions[cat] = round(score / total_category_score, 2)
                    
        # Sort all findings by severity for top findings
        top_findings = sorted(findings, key=lambda f: self.severity_weights.get(f.severity, 0.0), reverse=True)[:5]
        
        return risk_score, confidence, categories_breakdown, normalized_contributions, top_findings
