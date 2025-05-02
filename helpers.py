import shutil
from utils import colored_log


def check_dependency(cmd: str) -> bool:
    """Check if a CLI tool is available in system PATH"""
    return shutil.which(cmd) is not None
