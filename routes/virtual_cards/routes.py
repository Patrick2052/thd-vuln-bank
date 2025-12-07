from flask import Blueprint, jsonify
from pydantic import BaseModel

from config import SECURE_MODE
from database import execute_query

virtual_cards_bp = Blueprint("virtual-cards", __name__, "./static")

def get_auth_decorator():
    """Depending on secure mode get an insecure or secure auth decorator"""
    from auth import authorization_required, token_required

    if SECURE_MODE:
        return authorization_required
    else:
        # insecure token required decorator that also accepts cookie auth
        return token_required



@virtual_cards_bp.route(
    "/api/virtual-cards/<path:card_id>/toggle-freeze", methods=["POST"]
)
@get_auth_decorator()
def toggle_card_freeze(current_user, card_id):
    """Toggle the frozen state of a users virtual card in the database"""

    def _unsecure_card_freeze_route():
        """
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        !       UNSECURE ROUTE           !
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        """
        try:
            # Vulnerability: No CSRF protection
            # Vulnerability: BOLA - no verification if card belongs to user
            query = f"""
                UPDATE virtual_cards 
                SET is_frozen = NOT is_frozen 
                WHERE id = {card_id}
                RETURNING is_frozen
            """

            result = execute_query(query)

            if result:
                return jsonify(
                    {
                        "status": "success",
                        "message": f"Card {'frozen' if result[0][0] else 'unfrozen'} successfully",
                    }
                )

            return jsonify(
                {"status": "error", "message": "Card not found"}
            ), 404

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    def _secure_card_freeze_route():
        """
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        !       SECURE ROUTE             !
        !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        """
        try:
            # input validation for outside input
            if not isinstance(card_id, int) or card_id < 0:
                raise ValueError("Card id is not valid")

            query = """
                UPDATE virtual_cards 
                SET is_frozen = NOT is_frozen 
                WHERE id = %s and user_id = %s
                RETURNING is_frozen
            """

            result = execute_query(query, (card_id, current_user["user_id"]))

            if result:
                return jsonify(
                    {
                        "status": "success",
                        "message": f"Card {'frozen' if result[0][0] else 'unfrozen'} successfully",
                    }
                )

            return jsonify(
                {"status": "error", "message": "Card not found"}
            ), 404

        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    if SECURE_MODE:
        return _secure_card_freeze_route()
    else:
        return _unsecure_card_freeze_route()
