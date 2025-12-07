import time
from functools import wraps

from flask import jsonify, request

from auth import verify_token
from globals import rate_limit_storage

RATE_LIMIT_WINDOW = 3 * 60 * 60  # 3 hours in seconds
UNAUTHENTICATED_LIMIT = 5  # requests per IP per window
AUTHENTICATED_LIMIT = 10  # requests per user per window



def get_client_ip():
    """Get client IP address, considering proxy headers"""
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    elif request.headers.get("X-Real-IP"):
        return request.headers.get("X-Real-IP")
    else:
        return request.remote_addr


def cleanup_rate_limit_storage():
    """Clean up old entries from rate limit storage"""
    current_time = time.time()
    cutoff_time = current_time - RATE_LIMIT_WINDOW

    for key in list(rate_limit_storage.keys()):
        # Remove entries older than the rate limit window
        rate_limit_storage[key] = [
            (timestamp, count)
            for timestamp, count in rate_limit_storage[key]
            if timestamp > cutoff_time
        ]
        # Remove empty entries
        if not rate_limit_storage[key]:
            del rate_limit_storage[key]


def check_rate_limit(key, limit):
    """Check if the request should be rate limited"""
    cleanup_rate_limit_storage()
    current_time = time.time()

    # Count requests in the current window
    request_count = sum(
        count
        for timestamp, count in rate_limit_storage[key]
        if timestamp > current_time - RATE_LIMIT_WINDOW
    )

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
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            # Extract token and get user info
            token = auth_header.split(" ")[1]
            try:
                user_data = verify_token(token)
                if user_data:
                    # Authenticated mode: rate limit by both user and IP
                    user_key = f"ai_auth_user_{user_data['user_id']}"
                    ip_key = f"ai_auth_ip_{client_ip}"

                    # Check user-based rate limit
                    user_allowed, user_count, user_limit = check_rate_limit(
                        user_key, AUTHENTICATED_LIMIT
                    )
                    if not user_allowed:
                        return jsonify(
                            {
                                "status": "error",
                                "message": f"Rate limit exceeded for user. You have made {user_count} requests in the last 3 hours. Limit is {user_limit} requests per 3 hours.",
                                "rate_limit_info": {
                                    "limit_type": "authenticated_user",
                                    "current_count": user_count,
                                    "limit": user_limit,
                                    "window_hours": 3,
                                    "user_id": user_data["user_id"],
                                },
                            }
                        ), 429

                    # Check IP-based rate limit
                    ip_allowed, ip_count, ip_limit = check_rate_limit(
                        ip_key, AUTHENTICATED_LIMIT
                    )
                    if not ip_allowed:
                        return jsonify(
                            {
                                "status": "error",
                                "message": f"Rate limit exceeded for IP address. This IP has made {ip_count} requests in the last 3 hours. Limit is {ip_limit} requests per 3 hours.",
                                "rate_limit_info": {
                                    "limit_type": "authenticated_ip",
                                    "current_count": ip_count,
                                    "limit": ip_limit,
                                    "window_hours": 3,
                                    "client_ip": client_ip,
                                },
                            }
                        ), 429

                    # Both checks passed, proceed with authenticated function
                    return f(*args, **kwargs)
            except:
                pass  # Fall through to unauthenticated handling

        # Unauthenticated mode: rate limit by IP only
        ip_key = f"ai_unauth_ip_{client_ip}"
        ip_allowed, ip_count, ip_limit = check_rate_limit(
            ip_key, UNAUTHENTICATED_LIMIT
        )

        if not ip_allowed:
            return jsonify(
                {
                    "status": "error",
                    "message": f"Rate limit exceeded. This IP address has made {ip_count} requests in the last 3 hours. Limit is {ip_limit} requests per 3 hours for unauthenticated users.",
                    "rate_limit_info": {
                        "limit_type": "unauthenticated_ip",
                        "current_count": ip_count,
                        "limit": ip_limit,
                        "window_hours": 3,
                        "client_ip": client_ip,
                        "suggestion": "Log in to get higher rate limits (10 requests per 3 hours)",
                    },
                }
            ), 429

        # Rate limit check passed, proceed with unauthenticated function
        return f(*args, **kwargs)

    return decorated_function
