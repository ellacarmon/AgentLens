import unittest
from ai_guard.models.schema import Finding, Category, Severity
from ai_guard.engines.scoring import ScoringEngine

class TestScoringEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ScoringEngine()

    def test_single_critical_exec_triggers_high_risk(self):
        # A single eval() finding should trigger has_dynamic_exec → code_execution: 8.0
        findings = [
            Finding(rule_id="CODE_DYNAMIC_EXECUTION", category=Category.CODE_EXECUTION, severity=Severity.CRITICAL, 
                    file_path="f.py", description="eval", confidence=1.0)
        ]
        risk_score, risk_level, rec, conf, cats, _, _, features = self.engine.calculate(findings)
        # eval() triggers has_dynamic_exec(8) + execution_complexity=critical(9) → max = 9.0
        self.assertTrue(features["has_dynamic_exec"])
        self.assertEqual(features["execution_complexity"], "critical")
        self.assertEqual(cats["code_execution"], 9.0)
        self.assertGreaterEqual(risk_score, 8.0)
        self.assertIn(risk_level, ["HIGH", "CRITICAL"])
        self.assertEqual(rec, "BLOCK")

    def test_quantity_independence(self):
        # 1 exec finding and 50 exec findings should produce the SAME category score
        single = [
            Finding(rule_id="CODE_DYNAMIC_EXECUTION", category=Category.CODE_EXECUTION, severity=Severity.CRITICAL, 
                    file_path="f.py", description="eval", confidence=1.0)
        ]
        flood = [
            Finding(rule_id="CODE_DYNAMIC_EXECUTION", category=Category.CODE_EXECUTION, severity=Severity.CRITICAL, 
                    file_path=f"f{i}.py", description="eval", confidence=1.0)
            for i in range(50)
        ]
        _, _, _, _, cats_single, _, _, _ = self.engine.calculate(single)
        _, _, _, _, cats_flood, _, _, _ = self.engine.calculate(flood)
        self.assertEqual(cats_single["code_execution"], cats_flood["code_execution"])

    def test_subprocess_without_shell_is_low(self):
        # subprocess without shell=True → has_subprocess → code_execution: 3.0 → LOW
        findings = [
            Finding(rule_id="CODE_SUBPROCESS", category=Category.CODE_EXECUTION, severity=Severity.MEDIUM, 
                    file_path="f.py", description="subprocess.run", confidence=1.0)
        ]
        risk_score, risk_level, rec, _, cats, _, _, _ = self.engine.calculate(findings)
        self.assertEqual(cats["code_execution"], 3.0)
        self.assertEqual(risk_level, "LOW")
        self.assertEqual(rec, "ALLOW")

    def test_multi_category_aggregation(self):
        # Exec + prompt injection should combine via probabilistic OR
        findings = [
            Finding(rule_id="CODE_SHELL_EXECUTION", category=Category.CODE_EXECUTION, severity=Severity.HIGH, 
                    file_path="f.py", description="shell", confidence=1.0),
            Finding(rule_id="PROMPT_INJECTION_EXFIL", category=Category.PROMPT_INJECTION, severity=Severity.CRITICAL, 
                    file_path="g.md", description="exfil", confidence=1.0),
        ]
        risk_score, risk_level, _, _, cats, _, _, _ = self.engine.calculate(findings)
        # prompt_exfil triggers prompt_injection_severity=critical → 9.0
        self.assertEqual(cats["code_execution"], 7.0)
        self.assertEqual(cats["prompt_injection"], 9.0)
        self.assertGreater(risk_score, 9.0)

if __name__ == '__main__':
    unittest.main()
