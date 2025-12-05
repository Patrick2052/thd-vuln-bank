"""
# Register Route

## Known issues


"""

import random
import string
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request

from config import SECURE_MODE
from database import execute_query

register_bp = Blueprint("register", __name__, "./static")


def generate_account_number():
    return "".join(random.choices(string.digits, k=10))  # noqa: F821


@register_bp.route("/register", methods=["GET", "POST"], endpoint="register")
def register():
    """
    UNSECURE REGISTER ROUTE
    """
    if SECURE_MODE:
        return _secure_register_route()
    else:
        return _unsecure_register_route()


def _unsecure_register_route():
    if request.method == "POST":
        try:
            # Mass Assignment Vulnerability - Client can send additional parameters
            user_data = request.get_json()  # Changed to get_json()
            account_number = generate_account_number()

            # Check if username exists
            existing_user = execute_query(
                "SELECT username FROM users WHERE username = %s",
                (user_data.get("username"),),
            )

            if existing_user and existing_user[0]:
                return jsonify(
                    {
                        "status": "error",
                        "message": "Username already exists",
                        "username": user_data.get("username"),
                        "tried_at": str(
                            datetime.now()
                        ),  # Information disclosure
                    }
                ), 400

            # Build dynamic query based on user input fields
            # Vulnerability: Mass Assignment possible here
            fields = ["username", "password", "account_number"]
            values = [
                user_data.get("username"),
                user_data.get("password"),
                account_number,
            ]

            # Include any additional parameters from user input
            for key, value in user_data.items():
                if key not in ["username", "password"]:
                    fields.append(key)
                    values.append(value)

            # Build the SQL query dynamically
            query = f"""
                INSERT INTO users ({", ".join(fields)})
                VALUES ({", ".join(["%s"] * len(fields))})
                RETURNING id, username, account_number, balance, is_admin
            """

            result = execute_query(query, values, fetch=True)

            if not result or not result[0]:
                raise Exception("Failed to create user")

            user = result[0]

            # Excessive Data Exposure in Response
            sensitive_data = {
                "status": "success",
                "message": "Registration successful! Proceed to login",
                "debug_data": {  # Sensitive data exposed
                    "user_id": user[0],
                    "username": user[1],
                    "account_number": user[2],
                    "balance": float(user[3]) if user[3] else 1000.0,
                    "is_admin": user[4],
                    "registration_time": str(datetime.now()),
                    "server_info": request.headers.get("User-Agent"),
                    "raw_data": user_data,  # Exposing raw input data
                    "fields_registered": fields,  # Show what fields were registered
                },
            }

            response = jsonify(sensitive_data)
            response.headers["X-Debug-Info"] = str(
                sensitive_data["debug_data"]
            )
            response.headers["X-User-Info"] = (
                f"id={user[0]};admin={user[4]};balance={user[3]}"
            )

            return response

        except Exception as e:
            print(f"Registration error: {str(e)}")
            return jsonify(
                {
                    "status": "error",
                    "message": "Registration failed",
                    "error": str(e),
                }
            ), 500

    return render_template("register.html")


def _secure_register_route():
    return "not implemented", 500
