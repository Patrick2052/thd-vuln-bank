
# In-memory rate limiting storage
# Format: {key: [(timestamp, request_count), ...]}

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

rate_limit_storage = defaultdict(list)



@dataclass
class ChatContext:
    current_user: Optional[Dict[str, Any]] = None