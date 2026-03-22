import os
import re
from typing import List
from .base import BaseAnalyzer
from ..models.schema import Finding
from ..engines.rules import RuleEngine

class PromptAnalyzer(BaseAnalyzer):
    def __init__(self, rule_engine: RuleEngine):
        self.rules = rule_engine.get_rules_by_type("regex")

    def analyze(self, target_dir: str) -> List[Finding]:
        findings = []
        valid_extensions = {'.md', '.txt', '.prompt'}
        
        for root, _, files in os.walk(target_dir):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in valid_extensions or file.upper() in ['README', 'SKILL']:
                    filepath = os.path.join(root, file)
                    relative_path = os.path.relpath(filepath, target_dir)
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        # Match regex heuristics
                        for rule in self.rules:
                            pattern = rule.target
                            if isinstance(pattern, list):
                                pattern = "|".join(pattern)
                                
                            for match in re.finditer(pattern, content):
                                snippet_context = content[max(0, match.start()-30):min(len(content), match.end()+30)]
                                line_num = content.count('\\n', 0, match.start()) + 1
                                
                                conf = getattr(rule, 'confidence_base', 1.0)

                                # SKILL.md is the primary attack surface per Liu et al. (2026):
                                # 84.2% of confirmed vulnerabilities live in natural-language documentation.
                                # Invert default confidence logic for SKILL.md files.
                                skill_md_file = (
                                    file.lower() in ("skill.md", "skill")
                                    or file.upper() == "SKILL"
                                )
                                SKILL_MD_HIGH_CONF_RULES = {
                                    "SKILL_INSTRUCTION_OVERRIDE",
                                    "SKILL_BEHAVIOR_MANIPULATION",
                                    "SKILL_HIDDEN_INSTRUCTIONS",
                                }

                                if skill_md_file and rule.id in SKILL_MD_HIGH_CONF_RULES:
                                    # These patterns almost never appear in benign SKILL.md files
                                    conf = 0.9
                                elif ext == '.md' or file.upper() in ['README', 'SKILL']:
                                    if rule.category == Category.PROMPT_INJECTION:
                                        # Generic prompt injection in other docs remains low confidence
                                        conf = 0.2
                                        
                                findings.append(Finding(
                                    rule_id=rule.id,
                                    severity=rule.severity,
                                    category=rule.category,
                                    file_path=relative_path,
                                    line_number=line_num,
                                    description=rule.description,
                                    evidence=snippet_context.strip().replace('\\n', ' '),
                                    confidence=conf
                                ))
                    except Exception:
                        continue
                        
        return findings
