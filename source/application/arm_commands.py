"""Motion-command vocabulary spoken between the PC application and the arm.

Commands are short, newline-terminated ASCII lines. They travel as the
plaintext payload of an encrypted record (see security.SecureSession), so the
firmware decrypts a frame and parses one line:

    MOVE <dx> <dy>   steer the gripper; dx/dy are the desired travel direction
                     as signed integers in [-100, 100] (a unit vector * 100,
                     +x = right, +y = down to match image coordinates)
    GRIP             close the gripper
    RELEASE          open the gripper
    STOP             halt all motion, hold position
    HOME             return to the rest pose

This module is intentionally free of OpenCV/NumPy: it is the single source of
truth for the wire format and is unit-tested on its own.
"""
from __future__ import annotations

NEWLINE = b"\n"

GRIP = b"GRIP\n"
RELEASE = b"RELEASE\n"
STOP = b"STOP\n"
HOME = b"HOME\n"

# Magnitude a unit direction is scaled to on the wire.
MOVE_SCALE = 100


def unit_direction(dx: float, dy: float) -> tuple[int, int]:
    """Normalise a raw (dx, dy) pixel offset to an integer unit vector * 100.

    Returns (0, 0) for a zero-length input so callers can treat it as "no
    motion needed".
    """
    dist = (dx * dx + dy * dy) ** 0.5
    if dist == 0:
        return 0, 0
    ix = int(round(dx / dist * MOVE_SCALE))
    iy = int(round(dy / dist * MOVE_SCALE))
    return ix, iy


def encode_move(dx: int, dy: int) -> bytes:
    """Build a MOVE command line from an integer direction vector."""
    return f"MOVE {int(dx)} {int(dy)}\n".encode("ascii")


def direction_label(dx: float, dy: float, deadzone: float = 0.4) -> str:
    """Human-readable steering label (e.g. "UP + LEFT") for HUD/logging.

    A component is reported only when it is at least `deadzone` times the size
    of the other, matching the on-screen guidance in the original tracker.
    """
    parts = []
    if abs(dy) > abs(dx) * deadzone:
        parts.append("UP" if dy < 0 else "DOWN")
    if abs(dx) > abs(dy) * deadzone:
        parts.append("LEFT" if dx < 0 else "RIGHT")
    return " + ".join(parts)
