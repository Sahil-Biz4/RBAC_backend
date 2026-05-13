"""Unit tests for logging configuration."""

import logging

from app.core.logging_config import _SafeJsonFormatter, configure_logging


class TestSafeJsonFormatter:
    def test_renames_fields_when_rename_fields_set(self):
        formatter = _SafeJsonFormatter(fmt="%(message)s")
        formatter.rename_fields = {"levelname": "level"}
        log_record = {"levelname": "INFO", "message": "test"}
        formatter._perform_rename_log_fields(log_record)
        assert "level" in log_record
        assert "levelname" not in log_record

    def test_skips_rename_when_old_name_absent(self):
        formatter = _SafeJsonFormatter(fmt="%(message)s")
        formatter.rename_fields = {"nonexistent": "new_name"}
        log_record = {"message": "test"}
        formatter._perform_rename_log_fields(log_record)
        assert "new_name" not in log_record

    def test_noop_when_rename_fields_not_set(self):
        formatter = _SafeJsonFormatter(fmt="%(message)s")
        log_record = {"levelname": "INFO", "message": "test"}
        formatter._perform_rename_log_fields(log_record)
        assert "levelname" in log_record


class TestConfigureLogging:
    def test_configures_json_logging_for_production(self):
        configure_logging("production")
        root = logging.getLogger()
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, _SafeJsonFormatter)

    def test_configures_json_logging_for_staging(self):
        configure_logging("staging")
        root = logging.getLogger()
        assert isinstance(root.handlers[0].formatter, _SafeJsonFormatter)

    def test_configures_console_logging_for_local(self):
        configure_logging("local")
        root = logging.getLogger()
        assert isinstance(root.handlers[0].formatter, logging.Formatter)
        assert not isinstance(root.handlers[0].formatter, _SafeJsonFormatter)

    def test_configures_console_logging_for_development(self):
        configure_logging("development")
        root = logging.getLogger()
        assert isinstance(root.handlers[0].formatter, logging.Formatter)
