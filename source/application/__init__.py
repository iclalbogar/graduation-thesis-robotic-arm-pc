"""Application layer: camera-guided control of the robotic arm.

The vision pipeline (object_tracker) detects the arm gripper, the white balls
and the red/yellow zones, then computes a steering direction. The application
turns that direction into motion commands (arm_commands) and ships them to the
MCXN947 board over the encrypted USB channel (arm_controller -> SecureSession).

Only `arm_commands` and `arm_controller` are imported here: they are free of
OpenCV/NumPy so the test-suite and any headless consumer can use them without
the heavyweight vision dependencies. `app` and `object_tracker` import OpenCV
and are loaded explicitly when running the live application.
"""
from . import arm_commands
from .arm_controller import ArmController

__all__ = ["arm_commands", "ArmController"]
