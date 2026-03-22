from typing import Dict, Union

from ..models.schema import Category

class NormalizationLayer:
    """
    Feature-driven normalization:
    - Category score = max of triggered feature scores (not sum of findings)
    - Caps per category (max 10.0)
    - Probabilistic OR aggregation across categories
    """
    def __init__(self, feature_scores: Dict[str, Dict[str, float]]):
        self.feature_scores = feature_scores

    def compute_category_scores(self, features: Dict[str, Union[bool, int]]) -> Dict[str, float]:
        """
        Derive category scores purely from extracted features.
        
        For each category, look up which features are active and take the MAX
        of their configured scores. This makes scoring quantity-independent:
        1 exec or 50 execs → same category score.
        """
        categories_breakdown: Dict[str, float] = {cat.value: 0.0 for cat in Category}
        
        for category, feature_map in self.feature_scores.items():
            triggered_scores = []
            for feature_key, score_value in feature_map.items():
                feat_val = features.get(feature_key, False)
                # Feature is active if bool=True or count > 0
                if feat_val and feat_val is not False:
                    triggered_scores.append(float(score_value))
            
            if triggered_scores:
                # Max-based: category score = highest triggered feature score
                categories_breakdown[category] = round(min(10.0, max(triggered_scores)), 2)
                
        return categories_breakdown

    def aggregate_weighted_scores(self, categories_breakdown: Dict[str, float]) -> float:
        """Weighted aggregation using Probabilistic OR across the category space."""
        p_safe = 1.0
        for score_c in categories_breakdown.values():
            p_safe *= (1.0 - (score_c / 10.0))
            
        risk_score = 10.0 * (1.0 - p_safe)
        return round(risk_score, 2)
