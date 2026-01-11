from flask import jsonify, request
import jwt
import datetime
import sqlite3  
from functools import wraps
from datetime import datetime
from database import execute_query
from password import verify_password 
from pydantic import BaseModel
from config import settings

ALGORITHMS = ['HS256']

def check_password_strength(password):
    """
    Check password strength
    https://www.bsi.bund.de/EN/Themen/Verbraucherinnen-und-Verbraucher/Informationen-und-Empfehlungen/Cyber-Sicherheitsempfehlungen/Accountschutz/Sichere-Passwoerter-erstellen/sichere-passwoerter-erstellen_node.html
    """

    message="Password does not meet security guidelines: minimum 8 characters, at least one uppercase letter, one lowercase letter, one digit, and one special character"

    checks = [
        len(password) >= 8,
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(c in '!@#$%^&*()-_=+[]{}|;:,.<>?/' for c in password)
    ]
    if not all(checks):
        print(message)
        return False
    return True



def generate_token(user_id, username, is_admin=False):
    """
    Generate a JWT token with weak implementation
    Vulnerability: No token expiration (CWE-613)
    """
    now = int(datetime.now().timestamp())
    payload = {
        'user_id': user_id,
        'username': username,
        'is_admin': is_admin,
        'exp': now + 24 * 3600, 
        'iat': now
    }
    
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
    return token

def verify_token(token):
    """
    Verify JWT token and check expiration.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=ALGORITHMS)
        return payload
    except jwt.ExpiredSignatureError:
        print("Token verification error: Token has expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Token verification error: {str(e)}")
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Try to get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Handle 'Bearer' token format
                if 'Bearer' in auth_header:
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header
            except IndexError:
                token = None
                
        # Also check cookies (vulnerable by design)
        if not token and 'token' in request.cookies:
            token = request.cookies['token']
            
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            current_user = verify_token(token)
            if current_user is None:
                return jsonify({'error': 'Invalid token'}), 401
                
            return f(current_user, *args, **kwargs)
            
        except Exception as e:
            print(f"Token verification exception: {str(e)}")
            return jsonify({
                'error': 'Invalid token', 
            }), 401
            
    return decorated

def authorization_header_required(f):
    """
    Specific decorator for getting the auth token only from the authorization header

    Implementation of token_required for api endpoints that limits token location
    to header only to limit csrf exposure
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Try to get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Handle 'Bearer' token format
                if 'Bearer' in auth_header:
                    token = auth_header.split(' ')[1]
                else:
                    token = auth_header
            except IndexError:
                token = None
        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            current_user = verify_token(token)
            if current_user is None:
                return jsonify({'error': 'Invalid token'}), 401

            return f(current_user, *args, **kwargs)

        except Exception:
            return jsonify({
                'error': 'Invalid token', 
            }), 401
            
    return decorated



# New API endpoints with JWT authentication
def init_auth_routes(app):

    @app.route('/api/login', methods=['POST'])
    def api_login():

        class LoginRequestBody(BaseModel):
            username: str
            password: str

        try:
            data = LoginRequestBody(**request.get_json())
            username = data.username
            password = data.password

            user = execute_query("SELECT * FROM USERS WHERE USERNAME=%s", params=(username,))

            if user and len(user) > 0:
                user = user[0] 
                password_hash = user[2]
                if not verify_password(password, bytes(password_hash) ):
                    # TODO? Timing attack because of the different code paths?
                    return jsonify(
                        {
                            "status": "error",
                            "message": "Invalid credentials",
                            "debug_info": { # FIX no information disclosure of username
                                "time": str(datetime.now()),
                            },
                        }
                    ), 401

                token = generate_token(user[0], user[1], user[5])
                print(f"Debug - Generated token: {token}")  # Debug print

                return jsonify({
                    'token': token,
                    'user_id': user[0],
                    'username': user[1],
                })
            
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
            print(f"Login error: {str(e)}")  # Debug print
            return jsonify(
                {"status": "error", "message": "Login failed"}
            ), 500    # if not post request return this
