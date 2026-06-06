# Auth Module

JWT authentication and token blacklist for Open_Intel API.

## Components

- `token_blacklist.py` — Redis-backed token revocation for logout and account disable

## Usage

```python
from auth.token_blacklist import revoke_token, is_token_revoked
from api.auth import get_current_user, CurrentUser
```

## Configuration

Set `REDIS_URL` in `.env` to enable the token blacklist:

```
REDIS_URL=redis://localhost:6379/0
```

If `REDIS_URL` is not set, the blacklist is disabled and tokens remain valid until natural expiry.