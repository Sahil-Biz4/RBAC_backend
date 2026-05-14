"""Shared response-building helpers used across route layers."""

from app.core.constants import ResponseFields


def paginated_json(
    items_key: str,
    items: list[dict],
    total: int,
    page: int,
    limit: int,
    skip: int,
    **extra,
) -> dict:
    """Build the standard paginated success envelope.

    Any extra keyword arguments are merged into the returned dict, which allows
    callers to append optional fields (e.g. search=search) without custom code.
    """
    return {
        ResponseFields.SUCCESS: True,
        items_key: items,
        "total": total,
        "page": page,
        "limit": limit,
        "has_next": (skip + limit) < total,
        **extra,
    }
