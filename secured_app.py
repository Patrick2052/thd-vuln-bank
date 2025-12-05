# pylint: disable=line-too-long, missing-function-docstring, trailing-whitespace, pointless-string-statement

import html
import os
import platform
import random
import string
import time
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_cors import CORS
from flask_swagger_ui import get_swaggerui_blueprint
from werkzeug.utils import secure_filename

import auth
from ai_agent_deepseek import ai_agent
from auth import generate_token, init_auth_routes, token_required, verify_token
from database import (
    execute_query,
    execute_transaction,
    init_connection_pool,
    init_db,
)
from routes.login.routes import login_bp
from routes.register.routes import register_bp

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize database connection pool
init_connection_pool()

SWAGGER_URL = '/api/docs'
API_URL = '/static/openapi.json'

swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Vulnerable Bank API Documentation",
        'validatorUrl': None
    }
)

app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
app.register_blueprint(register_bp)
app.register_blueprint(login_bp)


# Hardcoded secret key (CWE-798)
app.secret_key = "secret123"

# Rate limiting configuration
RATE_LIMIT_WINDOW = 3 * 60 * 60  # 3 hours in seconds
UNAUTHENTICATED_LIMIT = 5  # requests per IP per window
AUTHENTICATED_LIMIT = 10   # requests per user per window

# In-memory rate limiting storage
# Format: {key: [(timestamp, request_count), ...]}
rate_limit_storage = defaultdict(list)

def cleanup_rate_limit_storage():
    """Clean up old entries from rate limit storage"""
    current_time = time.time()
    cutoff_time = current_time - RATE_LIMIT_WINDOW
    
    for key in list(rate_limit_storage.keys()):
        # Remove entries older than the rate limit window
        rate_limit_storage[key] = [
            (timestamp, count) for timestamp, count in rate_limit_storage[key]
            if timestamp > cutoff_time
        ]
        # Remove empty entries
        if not rate_limit_storage[key]:
            del rate_limit_storage[key]

def get_client_ip():
    """Get client IP address, considering proxy headers"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def check_rate_limit(key, limit):
    """Check if the request should be rate limited"""
    cleanup_rate_limit_storage()
    current_time = time.time()
    
    # Count requests in the current window
    request_count = sum(count for timestamp, count in rate_limit_storage[key] if timestamp > current_time - RATE_LIMIT_WINDOW)
    
    if request_count >= limit:
        return False, request_count, limit
    
    # Add current request
    rate_limit_storage[key].append((current_time, 1))
    return True, request_count + 1, limit

def ai_rate_limit(f):
    """Rate limiting decorator for AI endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = get_client_ip()
        
        # Check if this is an authenticated request
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            # Extract token and get user info
            token = auth_header.split(' ')[1]
            try:
                user_data = verify_token(token)
                if user_data:
                    # Authenticated mode: rate limit by both user and IP
                    user_key = f"ai_auth_user_{user_data['user_id']}"
                    ip_key = f"ai_auth_ip_{client_ip}"
                    
                    # Check user-based rate limit
                    user_allowed, user_count, user_limit = check_rate_limit(user_key, AUTHENTICATED_LIMIT)
                    if not user_allowed:
                        return jsonify({
                            'status': 'error',
                            'message': f'Rate limit exceeded for user. You have made {user_count} requests in the last 3 hours. Limit is {user_limit} requests per 3 hours.',
                            'rate_limit_info': {
                                'limit_type': 'authenticated_user',
                                'current_count': user_count,
                                'limit': user_limit,
                                'window_hours': 3,
                                'user_id': user_data['user_id']
                            }
                        }), 429
                    
                    # Check IP-based rate limit
                    ip_allowed, ip_count, ip_limit = check_rate_limit(ip_key, AUTHENTICATED_LIMIT)
                    if not ip_allowed:
                        return jsonify({
                            'status': 'error',
                            'message': f'Rate limit exceeded for IP address. This IP has made {ip_count} requests in the last 3 hours. Limit is {ip_limit} requests per 3 hours.',
                            'rate_limit_info': {
                                'limit_type': 'authenticated_ip',
                                'current_count': ip_count,
                                'limit': ip_limit,
                                'window_hours': 3,
                                'client_ip': client_ip
                            }
                        }), 429
                    
                    # Both checks passed, proceed with authenticated function
                    return f(*args, **kwargs)
            except:
                pass  # Fall through to unauthenticated handling
        
        # Unauthenticated mode: rate limit by IP only
        ip_key = f"ai_unauth_ip_{client_ip}"
        ip_allowed, ip_count, ip_limit = check_rate_limit(ip_key, UNAUTHENTICATED_LIMIT)
        
        if not ip_allowed:
            return jsonify({
                'status': 'error',
                'message': f'Rate limit exceeded. This IP address has made {ip_count} requests in the last 3 hours. Limit is {ip_limit} requests per 3 hours for unauthenticated users.',
                'rate_limit_info': {
                    'limit_type': 'unauthenticated_ip',
                    'current_count': ip_count,
                    'limit': ip_limit,
                    'window_hours': 3,
                    'client_ip': client_ip,
                    'suggestion': 'Log in to get higher rate limits (10 requests per 3 hours)'
                }
            }), 429
        
        # Rate limit check passed, proceed with unauthenticated function
        return f(*args, **kwargs)
    
    return decorated_function

UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def generate_account_number():
    return ''.join(random.choices(string.digits, k=10))

def generate_card_number():
    """Generate a 16-digit card number"""
    # Vulnerability: Predictable card number generation
    return ''.join(random.choices(string.digits, k=16))

def generate_cvv():
    """Generate a 3-digit CVV"""
    # Vulnerability: Predictable CVV generation
    return ''.join(random.choices(string.digits, k=3))

@app.route('/')
def index():
    return render_template('index.html')

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         try:
#             # Mass Assignment Vulnerability - Client can send additional parameters
#             user_data = request.get_json()  # Changed to get_json()
#             account_number = generate_account_number()
            
#             # Check if username exists
#             existing_user = execute_query(
#                 "SELECT username FROM users WHERE username = %s",
#                 (user_data.get('username'),)
#             )
            
#             if existing_user and existing_user[0]:
#                 return jsonify({
#                     'status': 'error',
#                     'message': 'Username already exists',
#                     'username': user_data.get('username'),
#                     'tried_at': str(datetime.now())  # Information disclosure
#                 }), 400
            
#             # Build dynamic query based on user input fields
#             # Vulnerability: Mass Assignment possible here
#             fields = ['username', 'password', 'account_number']
#             values = [user_data.get('username'), user_data.get('password'), account_number]
            
#             # Include any additional parameters from user input
#             for key, value in user_data.items():
#                 if key not in ['username', 'password']:
#                     fields.append(key)
#                     values.append(value)
            
#             # Build the SQL query dynamically
#             query = f"""
#                 INSERT INTO users ({', '.join(fields)})
#                 VALUES ({', '.join(['%s'] * len(fields))})
#                 RETURNING id, username, account_number, balance, is_admin
#             """
            
#             result = execute_query(query, values, fetch=True)
            
#             if not result or not result[0]:
#                 raise Exception("Failed to create user")
                
#             user = result[0]
            
#             # Excessive Data Exposure in Response
#             sensitive_data = {
#                 'status': 'success',
#                 'message': 'Registration successful! Proceed to login',
#                 'debug_data': {  # Sensitive data exposed
#                     'user_id': user[0],
#                     'username': user[1],
#                     'account_number': user[2],
#                     'balance': float(user[3]) if user[3] else 1000.0,
#                     'is_admin': user[4],
#                     'registration_time': str(datetime.now()),
#                     'server_info': request.headers.get('User-Agent'),
#                     'raw_data': user_data,  # Exposing raw input data
#                     'fields_registered': fields  # Show what fields were registered
#                 }
#             }
            
#             response = jsonify(sensitive_data)
#             response.headers['X-Debug-Info'] = str(sensitive_data['debug_data'])
#             response.headers['X-User-Info'] = f"id={user[0]};admin={user[4]};balance={user[3]}"
            
#             return response
                
#         except Exception as e:
#             print(f"Registration error: {str(e)}")
#             return jsonify({
#                 'status': 'error',
#                 'message': 'Registration failed',
#                 'error': str(e)
#             }), 500
        
#     return render_template('register.html')

# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         try:
#             data = request.get_json()
#             username = data.get('username')
#             password = data.get('password')
            
#             print(f"Login attempt - Username: {username}")  # Debug print
            
#             # SQL Injection vulnerability (intentionally vulnerable)
#             query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
#             print(f"Debug - Login query: {query}")  # Debug print

#             # !FIX FOR SQL INJECTION
#             """
#             use a sql string with arguments instead of string formatting
                        
#             ```
#             query = f"SELECT * FROM users WHERE username=%s AND password=%s
#             ```

#             then pass username and password to execute query as params and let psycopg2 handle
#             the parameter security

#             ```
#             user = execute_query(query, params=(username, password))
#             ```
#             """

#             # TODO no password check function because the password is stored in plain text

#             user = execute_query(query)
#             print(f"Debug - Query result: {user}")  # Debug print
            
#             if user and len(user) > 0:
#                 user = user[0]  # Get first row
#                 print(f"Debug - Found user: {user}")  # Debug print
                
#                 # Generate JWT token instead of using session
#                 token = generate_token(user[0], user[1], user[5])
#                 print(f"Debug - Generated token: {token}")  # Debug print
                
#                 response = make_response(jsonify({
#                     'status': 'success',
#                     'message': 'Login successful',
#                     'token': token,
#                     'accountNumber': user[3],
#                     'isAdmin':       user[5],
#                     'debug_info': {  # Vulnerability: Information disclosure
#                         'user_id': user[0],
#                         'username': user[1],
#                         'account_number': user[3],
#                         'is_admin': user[5],
#                         'login_time': str(datetime.now())
#                     }
#                 }))
#                 # Vulnerability: Cookie without secure flag
#                 response.set_cookie('token', token, httponly=True)
#                 return response
            
#             # Vulnerability: Username enumeration
#             return jsonify({
#                 'status': 'error',
#                 'message': 'Invalid credentials',
#                 'debug_info': {  # Vulnerability: Information disclosure
#                     'attempted_username': username,
#                     'time': str(datetime.now())
#                 }
#             }), 401
            
#         except Exception as e:
#             print(f"Login error: {str(e)}")
#             return jsonify({
#                 'status': 'error',
#                 'message': 'Login failed',
#                 'error': str(e)
#             }), 500
        
#     return render_template('login.html')