"""
ChiefWiggum Loop - Patch-driven vulnerability testing methodology
D'oh! I found it!
"""

__version__ = "0.1.0"
__author__ = "Security Research Team"

from .core import Evaluator, EvidenceType, ActionType, Evidence
from .project import create_project, load_project, init_in_place, init_from_url
from .hypothesis_generator import generate_hypotheses

__all__ = [
    "Evaluator",
    "EvidenceType",
    "ActionType",
    "Evidence",
    "create_project",
    "load_project",
    "init_in_place",
    "init_from_url",
    "generate_hypotheses",
]
