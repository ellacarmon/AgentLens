from typing import List
from ..models.schema import Finding

class BaseAnalyzer:
    def analyze(self, target_dir: str) -> List[Finding]:
        """Runs the static analysis over the target directory and returns findings."""
        raise NotImplementedError
