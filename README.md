# Auth Module — Reusable RBAC Authentication Backend

A production-ready, modular FastAPI authentication backend with full Role-Based Access Control (RBAC). Built to be dropped into any project.

---

## Features

- **JWT Auth** — Access token (15 min) + Refresh token (7 days) with rotation
- **RBAC** — Roles table + Permissions table, many-to-many, embedded in JWT
- **OTP Email Verification** — Dedicated `email_otps` table, rate-limited resend
- **Token Blacklisting** — `refresh_tokens` table; revoked on logout
- **Password Security** — Argon2 primary, PBKDF2-SHA256 legacy fallback
- **Admin Management** — Create/assign/revoke roles and permissions via API
- **Middleware Stack** — Auth, Security Headers, Request Logging with X-Request-ID
- **Zero Hardcoded Values** — All constants in `constants.py`, all config in `.env`

---

## Project Structure

```
app/
├── core/
│   ├── auth/           # jwt_handler, password, dependencies, rbac
│   ├── config/         # settings.py (loaded from .env)
│   ├── middleware/     # auth, request_logging, security_headers
│   └── services/       # email_service, email_templates
├── features/
│   ├── auth/           # register, login, refresh, logout, OTP, password reset
│   ├── users/          # CRUD endpoints (RBAC-protected)
│   └── admin/          # role & permission management
├── models/             # user, role, permission, associations, email_otp, refresh_token
├── utils/
│   ├── constants.py    # ResponseMessages, RoleNames, Permissions
│   └── helpers.py      # generate_otp, hash_otp, mask_email
└── main.py

alembic/versions/
├── 001_create_users.py
├── 002_create_roles_and_permissions.py
├── 003_create_associations.py
├── 004_create_email_otps.py
├── 005_create_refresh_tokens.py
└── 006_seed_roles_and_permissions.py
```

---

## Quick Start

### 1. Clone & install

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — set DATABASE_URL, JWT_SECRET_KEY, ADMIN_SECRET_KEY, SENDGRID_*, etc.
```

### 3. Run migrations

```bash
alembic upgrade head
```

### 4. Start the server

```bash
uvicorn app.main:app --reload
```

API docs available at: `http://localhost:8000/docs`

---

## RBAC Flow

```
User Login
    → credentials verified
    → roles + permissions loaded from DB
    → embedded in JWT access token

Per Request
    → AuthMiddleware decodes JWT → request.state.token_payload
    → Route dependency reads roles/permissions from payload (no DB hit)
    → require_role("admin") | require_permission("users:write") enforced

Token Refresh
    → refresh token JTI checked against DB (not revoked)
    → old refresh token revoked
    → fresh roles/permissions reloaded from DB
    → new token pair issued
```

---

## Default Roles & Permissions

| Role | Permissions |
|---|---|
| `super_admin` | All permissions |
| `admin` | `users:*`, `roles:read`, `permissions:read`, `profile:*` |
| `manager` | `users:read`, `roles:read`, `profile:*` |
| `user` | `profile:read`, `profile:write` |

---

## API Endpoints

### Auth — `/api/v1/auth` (public)

| Method | Path | Description |
|---|---|---|
| POST | `/register` | Register new user — sends email OTP |
| POST | `/register-admin` | Create admin (requires ADMIN_SECRET_KEY) |
| POST | `/login` | Login — returns access + refresh token |
| POST | `/refresh` | Rotate refresh token |
| POST | `/logout` | Revoke refresh token |
| POST | `/verify-otp` | Verify email OTP |
| POST | `/resend-otp` | Resend OTP (rate-limited) |
| POST | `/forgot-password` | Send password-reset OTP |
| POST | `/change-password` | Change password (requires reset token) |

### Users — `/api/v1/users` (authenticated)

| Method | Path | Permission Required |
|---|---|---|
| GET | `/me` | Any authenticated user |
| PUT | `/me` | Any authenticated user |
| GET | `/` | `users:read` |
| GET | `/{user_id}` | `users:read` |
| DELETE | `/{user_id}` | `users:delete` |

### Admin — `/api/v1/admin` (admin role required)

| Method | Path | Description |
|---|---|---|
| GET/POST | `/roles` | List / create roles |
| PUT/DELETE | `/roles/{role_id}` | Update / delete role |
| POST/DELETE | `/roles/{role_id}/permissions` | Assign / revoke permission from role |
| GET/POST | `/permissions` | List / create permissions |
| DELETE | `/permissions/{permission_id}` | Delete permission |
| GET/POST | `/users/{user_id}/roles` | Get / assign role to user |
| DELETE | `/users/{user_id}/roles/{role_id}` | Revoke role from user |

---

## RBAC Usage in Any Route

```python
from app.core.auth.rbac import require_role, require_permission, require_any_role

# Single role
@router.delete("/x", dependencies=[Depends(require_role("admin"))])

# Any of multiple roles
@router.get("/x", dependencies=[Depends(require_any_role(["admin", "manager"]))])

# Fine-grained permission
@router.post("/x", dependencies=[Depends(require_permission("users:write"))])
```

---

## Pre-commit Setup

```bash
pre-commit install
pre-commit run --all-files
```

Hooks: `trailing-whitespace`, `end-of-file-fixer`, `check-yaml`, `ruff` (lint + format), `black`
