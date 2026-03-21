import os
import subprocess
import tempfile
import click
from .ingestion import Target, TargetType

class Fetcher:
    def __init__(self, target: Target, verbose: bool = False):
        self.target = target
        self.verbose = verbose
        self._temp_dir = None

    def fetch(self) -> str:
        """Returns the absolute path to the staged contents."""
        if self.target.type == TargetType.LOCAL_PATH:
            return os.path.abspath(self.target.raw)
        
        elif self.target.type == TargetType.GITHUB_REPO:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="ai_guard_")
            staging_path = self._temp_dir.name
            if self.verbose:
                click.echo(f"VERBOSE: Cloning {self.target.raw} into {staging_path}", err=True)
            
            cmd = ["git", "clone", "--depth", "1", "--quiet", self.target.raw, staging_path]
            try:
                subprocess.run(cmd, check=True, capture_output=not self.verbose)
                return staging_path
            except subprocess.CalledProcessError as e:
                click.echo(click.style(f"Error cloning repository: {e.stderr if e.stderr else e}", fg="red"), err=True)
                raise
        else:
            raise ValueError(f"Unsupported target type: {self.target.type}")

    def cleanup(self):
        if self._temp_dir is not None:
            self._temp_dir.cleanup()
