"""Structured logging configuration.

Configures JSON structured logging for production/staging environments
and human-readable console logs for local/development.
Call ``configure_logging()`` once at application startup (in ``create_app``).
"""

import logging
import sys

from pythonjsonlogger import jsonlogger


class _SafeJsonFormatter(jsonlogger.JsonFormatter):
    """JSON formatter that safely handles optional field renaming."""

    def _perform_rename_log_fields(self, log_record: dict) -> None:
        if hasattr(self, "rename_fields") and self.rename_fields:
            for old_name, new_name in self.rename_fields.items():
                if old_name in log_record:
                    log_record[new_name] = log_record.pop(old_name)


def configure_logging(environment: str = "local") -> None:
    """Set up application-wide logging.

    Args:
        environment: Current runtime environment string.
                     ``production`` or ``staging`` → JSON structured logs.
                     Everything else → human-readable console logs.
    """
    use_json = environment in ("production", "staging")

    if use_json:
        formatter: logging.Formatter = _SafeJsonFormatter(
            fmt="%(timestamp)s %(level)s %(logger)s %(message)s %(pathname)s %(lineno)d",
            rename_fields={"levelname": "level", "name": "logger", "asctime": "timestamp"},
            timestamp=True,
        )
    else:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.handlers.clear()
    root.addHandler(handler)

    # Silence noisy third-party loggers
    for noisy in ("urllib3", "httpx", "asyncio", "sqlalchemy.engine"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger(__name__).info(
        "Logging configured",
        extra={"environment": environment, "format": "json" if use_json else "console"},
    )
