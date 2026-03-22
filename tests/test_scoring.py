import unittest
from ai_guard.models.schema import Finding, Category, Severity
from ai_guard.engines.scoring import ScoringEngine

class TestScoringEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ScoringEngine()

    def test_single_critical_exec_triggers_high_risk(self):
        findings = [
            Finding(rule_id="CODE_DYNAMIC_EXECUTION", category=Category.CODE_EXECUTION, severity=Severity.CRITICAL, 
                    file_path="f.py", description="eval", confidence=1.0)
        ]
        result = self.engine.calculate(findings)
        self.assertTrue(result["features"]["has_dynamic_exec"])
        self.assertEqual(result["features"]["execution_complexity"], "critical")
        self.assertEqual(result["categories"]["code_execution"], 9.0)
        self.assertGreaterEqual(result["risk_score"], 8.0)
        self.assertIn(result["decision"], ["block"])
        self.assertIn("code execution", result["reason"])

    def test_quantity_independence(self):
        single = [
            Finding(rule_id="CODE_DYNAMIC_EXECUTION", category=Category.CODE_EXECUTION, severity=Severity.CRITICAL, 
                    file_path="f.py", description="eval", confidence=1.0)
        ]
        flood = [
            Finding(rule_id="CODE_DYNAMIC_EXECUTION", category=Category.CODE_EXECUTION, severity=Severity.CRITICAL, 
                    file_path=f"f{i}.py", description="eval", confidence=1.0)
            for i in range(50)
        ]
        r1 = self.engine.calculate(single)
        r2 = self.engine.calculate(flood)
        self.assertEqual(r1["categories"]["code_execution"], r2["categories"]["code_execution"])

    def test_subprocess_without_shell_is_low(self):
        findings = [
            Finding(rule_id="CODE_SUBPROCESS", category=Category.CODE_EXECUTION, severity=Severity.MEDIUM, 
                    file_path="f.py", description="subprocess.run", confidence=1.0)
        ]
        result = self.engine.calculate(findings)
        self.assertEqual(result["categories"]["code_execution"], 3.0)
        self.assertEqual(result["decision"], "allow")
        self.assertIn("Minor", result["reason"])

    def test_decision_reason_is_generated(self):
        findings = [
            Finding(rule_id="CODE_SHELL_EXECUTION", category=Category.CODE_EXECUTION, severity=Severity.HIGH, 
                    file_path="f.py", description="shell", confidence=1.0),
            Finding(rule_id="PROMPT_INJECTION_EXFIL", category=Category.PROMPT_INJECTION, severity=Severity.CRITICAL, 
                    file_path="g.md", description="exfil", confidence=1.0),
        ]
        result = self.engine.calculate(findings)
        self.assertEqual(result["decision"], "block")
        self.assertIn("prompt injection", result["reason"])
        self.assertTrue(len(result["reason"]) > 10)

if __name__ == '__main__':
    unittest.main()
