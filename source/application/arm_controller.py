"""ArmController: turns high-level intents into encrypted USB commands.

It wraps a security.SecureSession (or anything exposing `send(bytes)`), and is
the only place the application talks to the board. Two guards keep the channel
sane during a ~30 fps control loop:

  * de-duplication — a state command (GRIP/RELEASE/STOP/HOME) is not resent
    while it is still the most recent command, so holding the gripper closed
    doesn't flood the link;
  * rate-limiting — a repeated MOVE in the same direction is throttled to one
    every `min_interval` seconds, acting as a heartbeat without spamming.

A new direction (or any other command) always goes out immediately.

With no session (or `dry_run=True`) the controller logs what it *would* send,
so the vision app is fully usable on a laptop with no board attached.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from . import arm_commands

logger = logging.getLogger(__name__)


class ArmController:
    def __init__(
        self,
        session=None,
        *,
        dry_run: bool = False,
        min_interval: float = 0.06,
        clock=time.monotonic,
    ) -> None:
        self._session = session
        self._dry_run = dry_run or session is None
        self._min_interval = min_interval
        self._clock = clock
        self._last_payload: Optional[bytes] = None
        self._last_sent: float = float("-inf")

    @property
    def dry_run(self) -> bool:
        return self._dry_run

    @property
    def last_command(self) -> Optional[bytes]:
        return self._last_payload

    # ---- high-level intents -------------------------------------------------
    def move(self, dx: int, dy: int) -> None:
        """Steer toward (dx, dy); an integer unit vector * 100."""
        self._send(arm_commands.encode_move(dx, dy), coalesce=True)

    def steer(self, dx: float, dy: float) -> None:
        """Steer toward a raw pixel offset (normalised here)."""
        ix, iy = arm_commands.unit_direction(dx, dy)
        self.move(ix, iy)

    def grip(self) -> None:
        self._send(arm_commands.GRIP, coalesce=False)

    def release(self) -> None:
        self._send(arm_commands.RELEASE, coalesce=False)

    def stop(self) -> None:
        self._send(arm_commands.STOP, coalesce=False)

    def home(self) -> None:
        self._send(arm_commands.HOME, coalesce=False)

    # ---- transport ----------------------------------------------------------
    def _send(self, payload: bytes, *, coalesce: bool) -> None:
        now = self._clock()
        if payload == self._last_payload:
            if not coalesce:
                # State command already in effect — nothing to do.
                return
            if now - self._last_sent < self._min_interval:
                # Same direction, sent too recently — throttle.
                return

        self._last_payload = payload
        self._last_sent = now

        if self._dry_run:
            logger.info("[DRY-RUN] arm <- %s", payload.decode("ascii").strip())
            return

        try:
            self._session.send(payload)
        except Exception as exc:  # keep the control loop alive on a glitch
            logger.error("arm command send failed (%s): %s",
                         payload.decode("ascii", "replace").strip(), exc)
