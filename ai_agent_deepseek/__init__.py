from config import SECURE_MODE

if SECURE_MODE:
    from .vulnerable_agent import VulnerableAIAgent
    ai_agent = VulnerableAIAgent()
else:
    from .secure_agent import SecureAIAgent
    ai_agent = SecureAIAgent()


__all__ = [
    "VulnerableAIAgent",
    "SecureAIAgent",
    "ai_agent"
]