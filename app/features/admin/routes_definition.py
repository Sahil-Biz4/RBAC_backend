"""Admin feature route path constants."""


class AdminRoutes:
    BASE = "/api/v1/admin"

    ROLES = "/roles"
    ROLE_BY_ID = "/roles/{role_id}"
    ROLE_PERMISSIONS = "/roles/{role_id}/permissions"
    ROLE_PERMISSION_BY_ID = "/roles/{role_id}/permissions/{permission_id}"

    PERMISSIONS = "/permissions"
    PERMISSION_BY_ID = "/permissions/{permission_id}"

    USER_ROLES = "/users/{user_id}/roles"
    USER_ROLE_BY_ID = "/users/{user_id}/roles/{role_id}"


routes = AdminRoutes()
