"""Control plane: run policy, health and the kill switch for many gateways from one place."""

from .store import ControlError, ControlStore
from .sync import ControlPlaneSync


def create_control_app(*args, **kwargs):
    """Build the control-plane FastAPI app (needs ``fairewall[proxy]``)."""
    from .app import create_control_app as _create
    return _create(*args, **kwargs)


__all__ = ["ControlError", "ControlStore", "ControlPlaneSync", "create_control_app"]
