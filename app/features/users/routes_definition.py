"""Users feature route path constants."""


class UsersRoutes:
    BASE = "/api/v1/users"
    ME = "/me"
    CHANGE_PASSWORD = "/me/change-password"
    BY_ID = "/{user_id}"


routes = UsersRoutes()
