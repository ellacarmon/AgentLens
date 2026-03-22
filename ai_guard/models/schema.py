from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Union

class Category(str, Enum):
    CODE_EXECUTION = "code_execution"
    PROMPT_INJECTION = "prompt_injection"
    SUPPLY_CHAIN = "supply_chain"
    FILESYSTEM_ACCESS = "filesystem_access"
    NETWORK_ACCESS = "network_access"

class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DecisionVerdict(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class Finding(BaseModel):
    rule_id: str
    category: Category
    severity: Severity
    file_path: str
    line_number: Optional[int] = None
    description: str
    evidence: Optional[str] = None
    confidence: float = 1.0

class DecisionResult(BaseModel):
    """Structured output of the decision engine."""
    risk_score: float = Field(ge=0.0, le=10.0)
    risk_level: RiskLevel
    decision: DecisionVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    top_risks: List[str] = Field(default_factory=list, description="Top contributing risk categories")
    explanation: str = Field(default="", description="Human-readable explanation of the decision")
    recommendation: str = Field(default="", description="Actionable guidance for the user")

class Report(BaseModel):
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    risk_level: str
    recommendation: str
    decision: str = ""
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    top_risks: List[str] = []
    explanation: str = ""
    summary: str
    categories: Dict[str, float]
    normalized_contributions: Dict[str, float]
    top_findings: List[Finding]
    features: Dict[str, Union[bool, int, str]] = {}
    capabilities: List[str]
    findings: List[Finding]
