import random
from datetime import datetime

from flask import Blueprint, jsonify, make_response, render_template, request
from pydantic import BaseModel

from auth import generate_token
from config import SECURE_MODE
from database import execute_query

login_bp = Blueprint("login", __name__, "./static")

class LoginRequestBody(BaseModel):
    username: str
    password: str


# TODO rate limit secure login
@login_bp.route("/login", methods=["GET", "POST"])
def login():
    def _secure_login():
        print("secure login route")
        if request.method == "POST":
            try:
                data = LoginRequestBody(**request.get_json())
                username = data.username
                password = data.password

                # TODO match password hashes
                query = "SELECT * FROM users WHERE username=%s AND password=%s"

                user = execute_query(query, params=(username, password))
                print(f"Debug - Query result: {user}")  # Debug print

                if user and len(user) > 0:
                    user = user[0]  # Get first row
                    print(f"Debug - Found user: {user}")  # Debug print

                    # Generate JWT token instead of using session
                    token = generate_token(user[0], user[1], user[5])
                    print(f"Debug - Generated token: {token}")  # Debug print

                    response = make_response(
                        jsonify(
                            {
                                "status": "success",
                                "message": "Login successful",
                                "token": token,
                                "accountNumber": user[3],
                                "isAdmin": user[5],
                                "debug_info": {  # Vulnerability: Information disclosure
                                    "user_id": user[0],
                                    "username": user[1],
                                    "account_number": user[3],
                                    "is_admin": user[5],
                                    "login_time": str(datetime.now()),
                                },
                            }
                        )
                    )
                    # Vulnerability: Cookie without secure flag
                    # FIX: cookies is secure and samesite strict only (limit csrf); secure = send only over https
                    response.set_cookie("token", token, httponly=True, secure=True, samesite="strict")
                    return response

                return jsonify(
                    {
                        "status": "error",
                        "message": "Invalid credentials",
                        "debug_info": { # FIX no information disclosure of username
                            "time": str(datetime.now()),
                        },
                    }
                ), 401

            except Exception as e:
                print(f"Login error: {str(e)}")
                return jsonify(
                    {"status": "error", "message": "Login failed", "error": str(e)}
                ), 500
        return render_template("login.html")


    def _unsecure_login():
        """
        Unsecure login taken from the base app.py file from vuln-bank
        """
        if request.method == "POST":
            try:
                data = request.get_json()
                username = data.get("username")
                password = data.get("password")

                print(f"Login attempt - Username: {username}")  # Debug print

                # SQL Injection vulnerability (intentionally vulnerable)
                query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
                print(f"Debug - Login query: {query}")  # Debug print

                user = execute_query(query)
                print(f"Debug - Query result: {user}")  # Debug print

                if user and len(user) > 0:
                    user = user[0]  # Get first row
                    print(f"Debug - Found user: {user}")  # Debug print

                    # Generate JWT token instead of using session
                    token = generate_token(user[0], user[1], user[5])
                    print(f"Debug - Generated token: {token}")  # Debug print

                    response = make_response(
                        jsonify(
                            {
                                "status": "success",
                                "message": "Login successful",
                                "token": token,
                                "accountNumber": user[3],
                                "isAdmin": user[5],
                                "debug_info": {  # Vulnerability: Information disclosure
                                    "user_id": user[0],
                                    "username": user[1],
                                    "account_number": user[3],
                                    "is_admin": user[5],
                                    "login_time": str(datetime.now()),
                                },
                            }
                        )
                    )
                    # Vulnerability: Cookie without secure flag
                    response.set_cookie("token", token, httponly=True)
                    return response

                # Vulnerability: Username enumeration
                return jsonify(
                    {
                        "status": "error",
                        "message": "Invalid credentials",
                        "debug_info": {  # Vulnerability: Information disclosure
                            "attempted_username": username,
                            "time": str(datetime.now()),
                        },
                    }
                ), 401

            except Exception as e:
                print(f"Login error: {str(e)}")
                return jsonify(
                    {"status": "error", "message": "Login failed", "error": str(e)}
                ), 500

        return render_template("login.html")


    if SECURE_MODE:
        return _secure_login()
    else:
        return _unsecure_login()




# TODO fix this
# Forgot password endpoint
@login_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if SECURE_MODE:
        return _secure_forgot_password()
    else:
        return _unsecure_forgot_password()


def _unsecure_forgot_password():
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


def _secure_forgot_password():
    return "not implemented in secure"
