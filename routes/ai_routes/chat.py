# AI CUSTOMER SUPPORT AGENT ROUTES (INTENTIONALLY VULNERABLE)
import html
import re

from flask import Blueprint, jsonify, request
from pydantic import BaseModel, ValidationError

from ai_agent_deepseek import ai_agent
from auth import token_required
from config import SECURE_MODE
from database import execute_query
from rate_limit import ai_rate_limit

bp = Blueprint("chat", __name__, './static')


def _sanitize_message(msg, max_len=1000):
    """FIX function"""
    if not isinstance(msg, str):
        return ""
    # remove control characters
    msg = re.sub(r"[\x00-\x1F\x7F]", " ", msg)
    msg = msg.strip()
    if len(msg) > max_len:
        msg = msg[:max_len]
    # escape HTML to avoid reflected injection in downstream UIs
    return html.escape(msg)


class ChatRequestBody(BaseModel):
    message: str




@bp.route("/api/ai/chat", methods=["POST"])
@ai_rate_limit
@token_required
def ai_chat_authenticated(current_user):

    def _unsecure_ai_chat_route():
        """
        Vulnerable AI Customer Support Chat (AUTHENTICATED MODE)

        VULNERABILITIES:
        - Prompt Injection (CWE-77)
        - Information Disclosure (CWE-200)
        - Broken Authorization (CWE-862)
        - Insufficient Input Validation (CWE-20)
        - Data Exposure to External API (with DeepSeek)
        """
        try:
            data = request.get_json()
            user_message = data.get("message", "")

            # VULNERABILITY: No input validation or sanitization
            if not user_message:
                return jsonify(
                    {"status": "error", "message": "Message is required"}
                ), 400

            # VULNERABILITY: Pass sensitive user context directly to AI
            # Fetch fresh user data from database (VULNERABILITY: Additional DB query)
            fresh_user_data = execute_query(
                "SELECT id, username, account_number, balance, is_admin, profile_picture FROM users WHERE id = %s",
                (current_user["user_id"],),
                fetch=True,
            )

            if fresh_user_data:
                user_data = fresh_user_data[0]
                user_context = {
                    "user_id": user_data[0],
                    "username": user_data[1],
                    "account_number": user_data[2],
                    "balance": float(user_data[3]) if user_data[3] else 0.0,
                    "is_admin": bool(user_data[4]),
                    "profile_picture": user_data[5],
                }
            else:
                # Fallback to token data if DB query fails
                user_context = {
                    "user_id": current_user["user_id"],
                    "username": current_user["username"],
                    "account_number": current_user.get("account_number"),
                    "is_admin": current_user.get("is_admin", False),
                    "balance": 0.0,  # Default if no data found
                    "profile_picture": None,
                }

            # VULNERABILITY: No rate limiting on AI calls
            print("passing user context to ai chatbot: ", user_context)
            response = ai_agent.chat(user_message, user_context)

            return jsonify(
                {
                    "status": "success",
                    "ai_response": response,
                    "mode": "authenticated",
                    "user_context_included": True,
                }
            )

        except Exception as e:
            # VULNERABILITY: Detailed error messages
            return jsonify(
                {
                    "status": "error",
                    "message": f"AI chat error: {str(e)}",
                    "system_info": ai_agent.get_system_info(),
                }
            ), 500

    def _secure_ai_chat_route():
        """
        Strategy to secure:

        - limit information that the chatbot gets (context)
        """
        # FIX added input validation
        data = request.get_json()
        if not isinstance(data, dict):
            raise ValueError("invalid message input")
        try:
            request_data = ChatRequestBody(**data)
        except ValidationError:
            return {
                "msg": "invalid request body"
            }


        try:
            fresh_user_data = execute_query(
                    "SELECT id, username, account_number, balance, is_admin, profile_picture FROM users WHERE id = %s",
                    (current_user["user_id"],),
                    fetch=True,
                )

            if fresh_user_data:
                user_data = fresh_user_data[0]
                limited_user_ctx = {
                    "user_id": user_data[0],
                    "username": user_data[1],
                    "account_number": user_data[2],
                    # "balance": float(user_data[3]) if user_data[3] else 0.0,
                    # "is_admin": bool(user_data[4]), # remove is_admin as the ai does not need to know it
                    "profile_picture": user_data[5],
                }
            else:
                # Fallback to token data if DB query fails
                limited_user_ctx = {
                    "user_id": current_user["user_id"],
                    "username": current_user["username"],
                    "account_number": current_user.get("account_number"),
                    # "is_admin": current_user.get("is_admin", False),
                    # "balance": 0.0,  # Default if no data found
                    "profile_picture": None,
                }
            user_message = request_data.message
            user_context = limited_user_ctx
            response = ai_agent.chat(user_message, user_context)

            return jsonify(
                {
                    "status": "success",
                    "ai_response": response,
                    "mode": "authenticated",
                    "user_context_included": True,
                }
            )
        except Exception as e:
            # VULNERABILITY: Detailed error messages
            print("Ai chat error ", e)

            return jsonify(
                {
                    "status": "error",
                    "message": "AI chat error"
                }
            ), 500


    if SECURE_MODE:
        return _secure_ai_chat_route()
    else:
        return _unsecure_ai_chat_route()