"""Unit tests for the arm command wire format."""
from application import arm_commands


class TestEncodeMove:
    def test_basic(self):
        assert arm_commands.encode_move(100, 0) == b"MOVE 100 0\n"
        assert arm_commands.encode_move(-100, 50) == b"MOVE -100 50\n"

    def test_coerces_floats_to_int(self):
        assert arm_commands.encode_move(12.0, -7.0) == b"MOVE 12 -7\n"

    def test_is_ascii_newline_terminated(self):
        out = arm_commands.encode_move(3, 4)
        assert out.endswith(b"\n")
        out.decode("ascii")  # must not raise


class TestUnitDirection:
    def test_zero_vector(self):
        assert arm_commands.unit_direction(0, 0) == (0, 0)

    def test_pure_axes_scale_to_100(self):
        assert arm_commands.unit_direction(0, 5) == (0, 100)
        assert arm_commands.unit_direction(-9, 0) == (-100, 0)

    def test_magnitude_is_normalised(self):
        ix, iy = arm_commands.unit_direction(30, 40)  # 3-4-5 triangle
        assert (ix, iy) == (60, 80)

    def test_result_magnitude_is_about_100(self):
        ix, iy = arm_commands.unit_direction(7, -13)
        mag = (ix * ix + iy * iy) ** 0.5
        assert abs(mag - 100) < 2


class TestDirectionLabel:
    def test_cardinal(self):
        assert arm_commands.direction_label(0, -10) == "UP"
        assert arm_commands.direction_label(0, 10) == "DOWN"
        assert arm_commands.direction_label(-10, 0) == "LEFT"
        assert arm_commands.direction_label(10, 0) == "RIGHT"

    def test_diagonal(self):
        assert arm_commands.direction_label(-10, -10) == "UP + LEFT"
        assert arm_commands.direction_label(10, 10) == "DOWN + RIGHT"

    def test_deadzone_drops_minor_axis(self):
        # dx dominates, dy within deadzone -> only the horizontal part.
        assert arm_commands.direction_label(100, 10) == "RIGHT"


def test_state_commands_are_distinct_and_terminated():
    cmds = [arm_commands.GRIP, arm_commands.RELEASE,
            arm_commands.STOP, arm_commands.HOME]
    assert len(set(cmds)) == 4
    for c in cmds:
        assert c.endswith(b"\n")
