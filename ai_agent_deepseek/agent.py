import abc
from abc import ABC
from typing import Any, Optional

from globals import ChatContext


class AIAgent(ABC):
    @abc.abstractmethod
    def chat(
        self,
        user_message: str,
        user_context=ChatContext | dict[str, any],
    ):
        """Process a user message and return a response dict."""
        raise NotImplementedError

    @abc.abstractmethod
    def get_system_info(self):
        """Return a dict describing the agent/system."""
        raise NotImplementedError

    @abc.abstractmethod
    def _call_deepseek_api(self, prompt):
        """Send the composed prompt to an LLM provider and return the text response."""
        raise NotImplementedError

    @abc.abstractmethod
    def _get_database_context(self, message, user_context):
        """Optionally fetch and return database context (as string) based on message and user context."""
        raise NotImplementedError

    @abc.abstractmethod
    def _should_include_database_info(self, message):
        """Decide whether database info should be included for the given message."""
        raise NotImplementedError

    @abc.abstractmethod
    def _is_prompt_injection_request(self, message):
        """Detect prompt-injection attempts in the message."""
        raise NotImplementedError

    @abc.abstractmethod
    def _generate_mock_response(self, prompt):
        """Produce a mock LLM response when an external API is unavailable."""
        raise NotImplementedError