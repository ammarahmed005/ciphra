"""
Role-Based Access Control policy.

Each role is mapped to the maximum sensitivity level it may access.
The RBACEngine enforces this mapping for every classified query.
"""
from app.models import RoleEnum, SensitivityEnum


# Ordered least -> most sensitive.
_SENS_LEVEL = {
    SensitivityEnum.PUBLIC: 0,
    SensitivityEnum.INTERNAL: 1,
    SensitivityEnum.CONFIDENTIAL: 2,
    SensitivityEnum.RESTRICTED: 3,
}

# Maximum sensitivity each role can read.
_ROLE_MAX_SENSITIVITY = {
    RoleEnum.GUEST: SensitivityEnum.PUBLIC,
    RoleEnum.EMPLOYEE: SensitivityEnum.INTERNAL,
    RoleEnum.MANAGER: SensitivityEnum.CONFIDENTIAL,
    RoleEnum.ADMIN: SensitivityEnum.RESTRICTED,
}


class RBACEngine:
    """Pure-function access control evaluator."""

    @staticmethod
    def max_sensitivity(role: RoleEnum) -> SensitivityEnum:
        return _ROLE_MAX_SENSITIVITY[role]

    @staticmethod
    def is_permitted(role: RoleEnum, classification: SensitivityEnum) -> bool:
        """True if a user with `role` may receive data classified at `classification`."""
        return _SENS_LEVEL[classification] <= _SENS_LEVEL[_ROLE_MAX_SENSITIVITY[role]]

    @staticmethod
    def deny_reason(role: RoleEnum, classification: SensitivityEnum) -> str:
        return (
            f"Access denied: your role '{role.value}' is limited to "
            f"'{_ROLE_MAX_SENSITIVITY[role].value}'-level data, "
            f"but this query is classified as '{classification.value}'."
        )
