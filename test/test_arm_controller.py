"""Tests for ArmController: dedupe, rate-limit, and graceful failure."""
import pytest

from application.arm_controller import ArmController


class FakeSession:
    """Records every payload handed to send()."""

    def __init__(self):
        self.sent = []

    def send(self, payload):
        self.sent.append(payload)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class TestSending:
    def test_move_is_sent(self):
        sess = FakeSession()
        ArmController(sess).move(100, 0)
        assert sess.sent == [b"MOVE 100 0\n"]

    def test_state_commands_sent(self):
        sess = FakeSession()
        c = ArmController(sess)
        c.grip()
        c.release()
        assert sess.sent == [b"GRIP\n", b"RELEASE\n"]

    def test_steer_normalises_then_sends(self):
        sess = FakeSession()
        ArmController(sess).steer(30, 40)
        assert sess.sent == [b"MOVE 60 80\n"]


class TestDedupe:
    def test_repeated_state_command_not_resent(self):
        sess = FakeSession()
        c = ArmController(sess)
        c.grip()
        c.grip()
        c.grip()
        assert sess.sent == [b"GRIP\n"]

    def test_state_command_resent_after_intervening_command(self):
        sess = FakeSession()
        c = ArmController(sess)
        c.grip()
        c.release()
        c.grip()
        assert sess.sent == [b"GRIP\n", b"RELEASE\n", b"GRIP\n"]


class TestRateLimit:
    def test_same_move_throttled_within_interval(self):
        sess = FakeSession()
        clk = FakeClock()
        c = ArmController(sess, min_interval=0.1, clock=clk)
        c.move(10, 0)
        clk.advance(0.05)
        c.move(10, 0)        # too soon -> dropped
        assert sess.sent == [b"MOVE 10 0\n"]

    def test_same_move_resent_as_heartbeat_after_interval(self):
        sess = FakeSession()
        clk = FakeClock()
        c = ArmController(sess, min_interval=0.1, clock=clk)
        c.move(10, 0)
        clk.advance(0.2)
        c.move(10, 0)        # interval elapsed -> heartbeat
        assert sess.sent == [b"MOVE 10 0\n", b"MOVE 10 0\n"]

    def test_direction_change_sent_immediately(self):
        sess = FakeSession()
        clk = FakeClock()
        c = ArmController(sess, min_interval=0.1, clock=clk)
        c.move(10, 0)
        c.move(0, 10)        # different direction -> not throttled
        assert sess.sent == [b"MOVE 10 0\n", b"MOVE 0 10\n"]


class TestDryRun:
    def test_no_session_is_dry_run(self):
        c = ArmController()
        assert c.dry_run is True
        c.move(1, 2)  # must not raise
        assert c.last_command == b"MOVE 1 2\n"

    def test_explicit_dry_run_does_not_touch_session(self):
        sess = FakeSession()
        c = ArmController(sess, dry_run=True)
        c.move(1, 2)
        c.grip()
        assert sess.sent == []


class TestFailureIsolation:
    def test_send_exception_does_not_propagate(self):
        class BrokenSession:
            def send(self, payload):
                raise RuntimeError("usb gone")

        c = ArmController(BrokenSession())
        c.move(1, 1)  # error is logged, loop keeps running
