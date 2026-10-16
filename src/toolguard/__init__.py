"""toolguard: an information-flow guard between LLM agents and their tools."""

from .approvals import (
    ApprovalOutcome,
    ApprovalRequest,
    CallbackApprover,
    ChainApprover,
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
    "ApprovalOutcome",
    "ApprovalRequest",
    "CallbackApprover",
    "ChainApprover",
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
