
# In-memory rate limiting storage
# Format: {key: [(timestamp, request_count), ...]}
from collections import defaultdict

rate_limit_storage = defaultdict(list)