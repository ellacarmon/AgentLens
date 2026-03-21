import os
from enum import Enum
from urllib.parse import urlparse

class TargetType(Enum):
    GITHUB_REPO = "github_repo"
    LOCAL_PATH = "local_path"
    UNKNOWN = "unknown"

class Target:
    def __init__(self, raw: str):
        self.raw = raw
        self.type = self._determine_type(raw)
    
    def _determine_type(self, raw: str) -> TargetType:
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            if parsed.netloc == "github.com":
                return TargetType.GITHUB_REPO
        elif os.path.exists(raw):
            return TargetType.LOCAL_PATH
        return TargetType.UNKNOWN
