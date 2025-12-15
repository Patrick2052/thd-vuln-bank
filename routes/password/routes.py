from database import execute_query
from flask import Blueprint, request, jsonify, render_template
import random
from datetime import datetime
from config import SECURE_MODE


password_bp = Blueprint("password", __name__, "./static")

@password_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    def _unsecure_forgot_password_route():
        if request.method == "POST":
            try:
                data = request.get_json()  # Changed to get_json()
                username = data.get("username")

                # Vulnerability: SQL Injection possible
                user = execute_query(
                    f"SELECT id FROM users WHERE username='{username}'"
                )

                if user:
                    # Weak reset pin logic (CWE-330)
                    # Using only 3 digits makes it easily guessable
                    reset_pin = str(random.randint(100, 999))

                    # Store the reset PIN in database (in plaintext - CWE-319)
                    execute_query(
                        "UPDATE users SET reset_pin = %s WHERE username = %s",
                        (reset_pin, username),
                        fetch=False,
                    )

                    # Vulnerability: Information disclosure
                    return jsonify(
                        {
                            "status": "success",
                            "message": "Reset PIN has been sent to your email.",
                            "debug_info": {  # Vulnerability: Information disclosure
                                "timestamp": str(datetime.now()),
                                "username": username,
                                "pin_length": len(reset_pin),
                                "pin": reset_pin,  # Intentionally exposing pin for learning
                            },
                        }
                    )
                else:
                    # Vulnerability: Username enumeration
                    return jsonify(
                        {"status": "error", "message": "User not found"}
                    ), 404

            except Exception as e:
                print(f"Forgot password error: {str(e)}")
                return jsonify({"status": "error", "message": str(e)}), 500

        return render_template("forgot_password.html")
        
    def _secure_forgot_password_route():
        return NotImplementedError()


    if SECURE_MODE:
        return _secure_forgot_password_route()
    else:
        return _unsecure_forgot_password_route()

# Reset password endpoint
@password_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():

    def _unsecure_reset_password_route():
        if request.method == "POST":
            try:
                data = request.get_json()
                username = data.get("username")
                reset_pin = data.get("reset_pin")
                new_password = data.get("new_password")

                # Vulnerability: No rate limiting on PIN attempts
                # Vulnerability: Timing attack possible in PIN verification
                user = execute_query(
                    "SELECT id FROM users WHERE username = %s AND reset_pin = %s",
                    (username, reset_pin),
                )

                if user:
                    # Vulnerability: No password complexity requirements
                    # Vulnerability: No password history check
                    execute_query(
                        "UPDATE users SET password = %s, reset_pin = NULL WHERE username = %s",
                        (new_password, username),
                        fetch=False,
                    )

                    return jsonify(
                        {
                            "status": "success",
                            "message": "Password has been reset successfully",
                        }
                    )
                else:
                    # Vulnerability: Username enumeration possible
                    return jsonify(
                        {"status": "error", "message": "Invalid reset PIN"}
                    ), 400

            except Exception as e:
                # Vulnerability: Detailed error exposure
                print(f"Reset password error: {str(e)}")
                return jsonify(
                    {
                        "status": "error",
                        "message": "Password reset failed",
                        "error": str(e),
                    }
                ), 500

        return render_template("reset_password.html")

    # TODO
    def _secure_reset_password_route():
        raise NotImplementedError()