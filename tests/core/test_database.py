"""Unit tests for app/core/database._normalize_database_url."""

from app.core.database import _normalize_database_url


class TestNormalizeDatabaseUrl:
    def test_empty_string_returns_empty(self) -> None:
        assert _normalize_database_url("") == ""

    def test_postgres_scheme_converted(self) -> None:
        url = _normalize_database_url("postgres://user:pass@host/db")
        assert url.startswith("postgresql+psycopg://")

    def test_postgresql_sync_scheme_converted(self) -> None:
        url = _normalize_database_url("postgresql://user:pass@host/db")
        assert url.startswith("postgresql+psycopg://")

    def test_already_psycopg_unchanged(self) -> None:
        original = "postgresql+psycopg://user:pass@host/db"
        assert _normalize_database_url(original) == original

    def test_sqlite_unchanged(self) -> None:
        original = "sqlite+aiosqlite:///./test.db"
        assert _normalize_database_url(original) == original

    def test_asyncpg_scheme_without_asyncpg_installed(self, monkeypatch) -> None:
        """When asyncpg is not importable, asyncpg:// is converted to psycopg://."""
        import builtins

        real_import = builtins.__import__

        def _block_asyncpg(name, *args, **kwargs):
            if name == "asyncpg":
                raise ImportError("asyncpg not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _block_asyncpg)
        url = _normalize_database_url("postgresql+asyncpg://user:pass@host/db")
        assert url.startswith("postgresql+psycopg://")

    def test_host_and_path_preserved_after_conversion(self) -> None:
        url = _normalize_database_url("postgresql://myuser:mypass@localhost:5432/mydb")
        assert "myuser:mypass@localhost:5432/mydb" in url

    def test_postgres_shorthand_host_preserved(self) -> None:
        url = _normalize_database_url("postgres://u:p@db.example.com:5432/prod")
        assert "u:p@db.example.com:5432/prod" in url
