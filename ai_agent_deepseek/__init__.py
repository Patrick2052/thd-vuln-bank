from config import SECURE_MODE

from .secure_agent import SecureAIAgent
from .vulnerable_agent import VulnerableAIAgent

if SECURE_MODE:
    ai_agent = VulnerableAIAgent()
else:
    ai_agent = SecureAIAgent()


__all__ = [
    "VulnerableAIAgent",
    "SecureAIAgent",
    "ai_agent"
]