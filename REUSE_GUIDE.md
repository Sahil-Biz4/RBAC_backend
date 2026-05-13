# Backend Reuse Guide

FastAPI + SQLAlchemy + Redis auth/RBAC scaffold. Drop it in, configure env vars,
add your feature folders, and ship. The auth plumbing never needs touching.

---

## Quick start (new project)

```bash
git clone <this-repo> my-project-backend
cd my-project-backend
git remote set-url origin <new-repo-url>

cp .env.example .env.local        # fill in values — see §1 below
pip install -r requirements.txt
alembic upgrade head              # creates tables + seeds default roles/permissions
uvicorn app.main:app --reload
```

---

## 1. Environment variables to set first

### Identity (branding)

| Variable | What it drives |
|---|---|
| `PROJECT_NAME` | FastAPI docs title (`/docs`) |
| `APP_NAME` | Email subject lines and HTML email header |
| `SUPPORT_EMAIL` | Contact link inside OTP emails |
| `BRAND_COLOR` | Hex colour used in email templates |

### Secrets (generate fresh values for every project)

```bash
openssl rand -hex 32   # use once for JWT_SECRET_KEY, once for ADMIN_SECRET_KEY
```

| Variable | Notes |
|---|---|
| `JWT_SECRET_KEY` | Signs all JWTs — must be unique per project |
| `ADMIN_SECRET_KEY` | Required to hit `POST /api/v1/auth/register-admin` |

### Infrastructure

```env
DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/my_db
REDIS_URL=redis://localhost:6379/0
SENDGRID_API_KEY=SG.xxxx
SENDGRID_FROM_EMAIL=noreply@myapp.com
CORS_ORIGINS=https://myapp.com,http://localhost:3000
```

### Permissions scope (optional)

These control which `resource:action` combinations are valid when creating a permission
via the API. Extend them to match your domain.

```env
ALLOWED_RESOURCES=users,roles,permissions,profile,orders,products
ALLOWED_ACTIONS=read,create,update,delete,export,approve
```

---

## 2. Adding a new feature

Follow the four-file pattern used by every existing feature:

```
app/features/orders/
├── __init__.py
├── routes_definition.py   # path constants only
├── schemas.py             # Pydantic request/response models
├── repository.py          # SQLAlchemy queries — flush, never commit
├── service.py             # business logic — raises domain exceptions
└── routes.py              # FastAPI router — thin HTTP wrapper, calls service
```

### Repository rules

- Use `await db.flush()` inside repo functions, never `await db.commit()`
- Commit happens once, at the end of the service function that owns the transaction

### Service rules

- Raise domain exceptions (`NotFoundError`, `ConflictError`, `BadRequestError`, etc.) — never HTTP exceptions
- Import from `app.core.exceptions`

### Route rules

- Call `service.*` only — no repo imports in routes
- Wrap calls in `try / except AppError as exc: raise exc.as_http_exception()`
- Add `@limiter.limit("60/minute")` on GETs, `@limiter.limit("30/minute")` on mutations
- slowapi requires `request: Request` as the first parameter on every decorated handler

### Register the router in `app/main.py`

```python
from app.features.orders.routes import router as orders_router
app.include_router(orders_router, prefix="/api/v1")
```

---

## 3. Adding domain permissions

**Step 1** — Add constants to `app/utils/constants.py`:

```python
class Permissions:
    # ... existing ...
    ORDERS_READ   = "orders:read"
    ORDERS_CREATE = "orders:create"
    ORDERS_UPDATE = "orders:update"
    ORDERS_DELETE = "orders:delete"
```

**Step 2** — Assign to roles in `DEFAULT_ROLE_PERMISSIONS` (same file) so the next
`alembic upgrade head` seeds them automatically.

**Step 3** — Extend `ALLOWED_RESOURCES` in `.env.local`:

```env
ALLOWED_RESOURCES=users,roles,permissions,profile,orders
```

**Step 4** — Protect routes:

```python
from app.core.auth.rbac import require_permission
from app.utils.constants import Permissions

@router.get("/orders", dependencies=[Depends(require_permission(Permissions.ORDERS_READ))])
async def list_orders(...):
    ...
```

---

## 4. Adding a new database model

```python
# app/models/order.py
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.models.base import Base

class Order(Base):
    __tablename__ = "orders"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(50), default="pending")
```

Import it in `app/models/__init__.py` so Alembic picks it up, then generate a migration:

```bash
alembic revision --autogenerate -m "add orders table"
alembic upgrade head
```

---

## 5. Alembic migrations checklist

Before running `alembic upgrade head` on a new project, check the seed migration:

```
alembic/versions/..._assign_super_admin_to_first_user.py
```

It seeds default roles and their permissions from `DEFAULT_ROLE_PERMISSIONS`. Adjust
that mapping if your project needs a different default permission set before running.

---

## 6. What you never need to change

| Module | What it does |
|---|---|
| `app/core/auth/` | JWT creation/decode, password hashing, RBAC dependency, session dependencies |
| `app/core/services/redis_service.py` | Refresh token + JTI storage |
| `app/core/middleware/` | Auth, request logging, security headers |
| `app/core/exceptions.py` | Domain exception hierarchy |
| `app/features/auth/` | Full register/login/OTP/refresh/logout/password-reset flow |
| `app/features/admin/` | Role, permission, and user↔role management endpoints |

---

## 7. Per-project checklist

- [ ] `cp .env.example .env.local` and fill all values
- [ ] Set `PROJECT_NAME`, `APP_NAME`, `SUPPORT_EMAIL`, `BRAND_COLOR`
- [ ] Generate fresh `JWT_SECRET_KEY` and `ADMIN_SECRET_KEY` (`openssl rand -hex 32`)
- [ ] Point `DATABASE_URL` at the new database
- [ ] Review seed migration — adjust `DEFAULT_ROLE_PERMISSIONS` if needed
- [ ] `alembic upgrade head`
- [ ] Extend `ALLOWED_RESOURCES` / `ALLOWED_ACTIONS` to match your domain
- [ ] Add feature folders following §2
- [ ] Add domain permissions following §3
- [ ] Update `VERSION` in `app/utils/constants.py` as the project evolves
