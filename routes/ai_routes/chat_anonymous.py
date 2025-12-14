import json

from flask import Blueprint, jsonify, request
from pydantic import BaseModel

from ai_agent_deepseek import ai_agent
from config import SECURE_MODE
from rate_limit import ai_rate_limit

bp = Blueprint("chat_anonymous", __name__, './static')


class RouteBody(BaseModel):
    message: str


@bp.route("/api/ai/chat/anonymous", methods=["POST"])
@ai_rate_limit
def ai_chat_anonymous():
    def _unsecure_route():
        """
        Anonymous AI chat endpoint (UNAUTHENTICATED MODE)

        VULNERABILITIES:
        - No authentication required
        - Direct database access possible
        - System information exposure
        - Still vulnerable to prompt injection
        """
        try:
            data = request.get_json()
            user_message = data.get("message", "")

            if not user_message:
                return jsonify(
                    {"status": "error", "message": "Message is required"}
                ), 400

            # VULNERABILITY: No user context means no authorization but still dangerous
            response = ai_agent.chat(user_message, None)

            return jsonify(
                {
                    "status": "success",
                    "ai_response": response,
                    "mode": "anonymous",
                    "warning": "This endpoint has no authentication - for demo purposes only",
                }
            )

        except Exception as e:
            return jsonify(
                {
                    "status": "error",
                    "message": f"Anonymous AI chat error: {str(e)}",
                    "system_info": ai_agent.get_system_info(),
                }
            ), 500

    def _secure_route():
        body = request.get_json()
        body = RouteBody(**body)


        return "TODO"


    if SECURE_MODE:
        return _secure_route()
    else:
        return _unsecure_route()