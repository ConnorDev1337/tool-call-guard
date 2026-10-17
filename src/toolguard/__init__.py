"""toolguard: an information-flow guard between LLM agents and their tools."""

from .approvals import (
    ApprovalConfig,
    ApprovalOutcome,
    ApprovalRequest,
    CallbackApprover,
    ChainApprover,
    ChallengeSettings,
    ConsoleApprover,
    DenyApprover,
    QueueApprover,
)
from .guard import Guard
from .model import Action, Decision, Evidence, Observation, Reason, ToolBlocked
from .policy import Policy, PolicyError
from .store import Store

__version__ = "0.1.0"

__all__ = [
    "Action",
    "ApprovalConfig",
    "ApprovalOutcome",
    "ApprovalRequest",
    "CallbackApprover",
    "ChainApprover",
    "ChallengeSettings",
    "ConsoleApprover",
    "Decision",
    "DenyApprover",
    "Evidence",
    "Guard",
    "Observation",
    "Policy",
    "PolicyError",
    "QueueApprover",
    "Reason",
    "Store",
    "ToolBlocked",
    "__version__",
]
