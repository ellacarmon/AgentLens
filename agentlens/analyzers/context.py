import os
from typing import Dict, Any
from .logic_audit import is_ai_skill_path

class ContextAnalyzer:
    """
    Lightweight analyzer to infer context signals from the repository structure.
    Used to adjust scoring (e.g., distinguishing a safe framework runtime vs a script).
    """
    
    def analyze(self, target_dir: str) -> Dict[str, Any]:
        context = {
            "is_framework": False,
            "is_library": False,
            "exec_exposed_to_user": True,
            "is_ai_skill": is_ai_skill_path(target_dir),
        }
        
        # Check for common library/framework indicators
        indicators = ["setup.py", "pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock"]
        for ind in indicators:
            if os.path.exists(os.path.join(target_dir, ind)):
                context["is_framework"] = True
                context["is_library"] = True
                context["exec_exposed_to_user"] = False
                break
                
        return context
