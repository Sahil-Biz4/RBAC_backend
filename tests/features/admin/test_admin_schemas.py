"""Unit tests for admin feature Pydantic schemas — validator edge cases."""

import pytest
from pydantic import ValidationError

from app.features.admin.schemas import PermissionIn


class TestPermissionIn:
    def test_valid_permission_passes(self):
        perm = PermissionIn(name="users:read", resource="users", action="read")
        assert perm.name == "users:read"

    def test_resource_mismatch_raises_validation_error(self):
        """name resource part must match resource field."""
        with pytest.raises(ValidationError):
            PermissionIn(name="roles:read", resource="users", action="read")

    def test_action_mismatch_raises_validation_error(self):
        """name action part must match action field — covers line 66."""
        with pytest.raises(ValidationError):
            PermissionIn(name="users:write", resource="users", action="read")

    def test_disallowed_resource_raises_validation_error(self):
        with pytest.raises(ValidationError):
            PermissionIn(name="billing:read", resource="billing", action="read")

    def test_disallowed_action_raises_validation_error(self):
        with pytest.raises(ValidationError):
            PermissionIn(name="users:purge", resource="users", action="purge")

    def test_name_without_colon_raises_validation_error(self):
        """name must match pattern requiring a colon, so no-colon input is caught at field level."""
        with pytest.raises(ValidationError):
            PermissionIn(name="usersread", resource="users", action="read")

    def test_validate_name_matches_parts_no_colon_branch(self):
        """Directly invoke model_validator with no-colon name to cover line 54."""
        obj = PermissionIn.model_construct(name="nocolon", resource="users", action="read", description=None)
        with pytest.raises(ValueError, match="resource:action"):
            obj.validate_name_matches_parts()

    def test_validate_name_matches_parts_multiple_colons_branch(self):
        """Directly invoke model_validator with multiple colons to cover line 58."""
        obj = PermissionIn.model_construct(name="users:read:extra", resource="users", action="read", description=None)
        with pytest.raises(ValueError, match="exactly one colon"):
            obj.validate_name_matches_parts()
