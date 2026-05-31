"""Camera-guided robotic-arm application.

Closes the loop: a webcam watches the table, the vision tracker locates the
gripper / balls / zones, a small state machine decides where the gripper should
go next, and every decision is shipped to the MCXN947 board as an encrypted
motion command over USB.

Pipeline:

    camera -> SceneTracker -> guidance state machine -> ArmController
                                                          -> SecureSession
                                                          -> MCXN947_USB_Comm

Run live (board attached):

    python -m application.app                     # from the `source/` dir
    python source/application/app.py              # from the repo root

Run vision-only (no board / dry-run, just logs the commands it would send):

    python source/application/app.py --dry-run

Keys (focus the "Arm Guidance" window):
    l  lock the current red-side ball count and start picking
    d  manually mark the current target as dropped
    g  calibrate the gripper (then click on it)
    G  clear gripper calibration (back to auto-detect)
    u  unlock and re-scan        r  reset to SCAN
    q  quit
"""
from __future__ import annotations

import argparse
import logging
import os
import sys

import cv2

# Allow running both as a module (`python -m application.app`) and as a script
# (`python source/application/app.py`), where `source/` isn't yet on the path.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from application.arm_controller import ArmController
    from application.object_tracker import SceneTracker
else:
    from .arm_controller import ArmController
    from .object_tracker import SceneTracker

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("application")

REACHED_THRESHOLD = 40  # pixels — gripper "on top of" a target
HOLDING_RADIUS = 55     # pixels — ball this close to gripper = considered held
ARROW_LENGTH = 100

# Default board identity (matches communication/communication_usb.py).
DEFAULT_VID = 0x1FC9
DEFAULT_PID = 0xA2


def draw_guidance(frame, arm_pos, target_pos, label_prefix):
    """Draw the steering arrow/labels and return (reached, dx_unit, dy_unit).

    dx_unit/dy_unit are the normalised travel direction (0.0 when reached) so
    the caller can forward them to the arm controller.
    """
    ax, ay = arm_pos
    tx, ty = target_pos
    dx, dy = tx - ax, ty - ay
    dist = (dx * dx + dy * dy) ** 0.5

    cv2.line(frame, arm_pos, target_pos, (255, 160, 0), 1, cv2.LINE_AA)
    cv2.circle(frame, target_pos, 12, (0, 255, 80), 2)

    w = frame.shape[1]
    label_x = w // 2

    if dist < REACHED_THRESHOLD:
        cv2.putText(frame, f"{label_prefix}: REACHED", (label_x - 160, 40),
                    cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 255, 80), 3)
        return True, 0.0, 0.0

    nx, ny = dx / dist, dy / dist
    arrow_end = (int(ax + nx * ARROW_LENGTH), int(ay + ny * ARROW_LENGTH))
    cv2.arrowedLine(frame, arm_pos, arrow_end, (30, 120, 255), 4, tipLength=0.35)

    parts = []
    if abs(dy) > abs(dx) * 0.4:
        parts.append("UP" if dy < 0 else "DOWN")
    if abs(dx) > abs(dy) * 0.4:
        parts.append("LEFT" if dx < 0 else "RIGHT")
    direction = " + ".join(parts)

    cv2.putText(frame, f"{label_prefix}: {direction}",
                (label_x - 180, 40),
                cv2.FONT_HERSHEY_SIMPLEX, 0.9, (30, 120, 255), 3)
    cv2.putText(frame, f"{int(dist)} px", (label_x - 28, 70),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (180, 180, 180), 2)
    return False, nx, ny


def build_controller(args) -> ArmController:
    """Set up the encrypted USB link and return an ArmController.

    Falls back to a dry-run controller (logs commands, no board) when --dry-run
    is given or when the board can't be reached, so the vision app always runs.
    """
    if args.dry_run:
        logger.info("Dry-run mode: arm commands will be logged, not sent.")
        return ArmController(dry_run=True)

    # Imported lazily so --dry-run works without pyusb / libusb installed.
    from communication.communication_usb import MCXN947_USB_Comm
    from security.session import SecureSession, SessionError

    mcx = MCXN947_USB_Comm(vid=args.vid, pid=args.pid, timeout=2000)
    if not mcx.connect():
        logger.warning("Board not found — continuing in dry-run mode.")
        return ArmController(dry_run=True)

    session = SecureSession(mcx)
    try:
        logger.info("Starting ECDH P-256 handshake with the board...")
        session.handshake()
        logger.info("Secure channel established (AES-256-CBC + AES-CMAC).")
    except SessionError as exc:
        logger.error("Handshake failed (%s) — continuing in dry-run mode.", exc)
        mcx.disconnect()
        return ArmController(dry_run=True)

    controller = ArmController(session, min_interval=args.min_interval)
    # Stash transport handles so the caller can tear them down cleanly.
    controller._session_obj = session  # noqa: SLF001 - app-internal bookkeeping
    controller._comm_obj = mcx          # noqa: SLF001
    return controller


def shutdown_controller(controller: ArmController) -> None:
    session = getattr(controller, "_session_obj", None)
    comm = getattr(controller, "_comm_obj", None)
    if session is not None:
        try:
            controller.stop()
            session.close()
        except Exception:
            pass
    if comm is not None:
        try:
            comm.disconnect()
        except Exception:
            pass


def run(args) -> int:
    cap = cv2.VideoCapture(args.camera)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
    if not cap.isOpened():
        logger.error("Cannot open camera index %d.", args.camera)
        return 1

    controller = build_controller(args)

    scene = SceneTracker()
    mode = "SCAN"            # SCAN -> PICK -> DROP -> ... -> DONE
    current_target_id = None
    drop_hold_frames = 0
    calibrating_gripper = {"on": False}
    state = {"frame": None}

    def on_mouse(event, x, y, _flags, _param):
        if calibrating_gripper["on"] and event == cv2.EVENT_LBUTTONDOWN \
                and state["frame"] is not None:
            if scene.calibrate_gripper(state["frame"], x, y):
                logger.info("[Gripper] template locked at (%d, %d)", x, y)
            else:
                logger.info("[Gripper] cannot calibrate — click too close to edge.")
            calibrating_gripper["on"] = False

    cv2.namedWindow("Arm Guidance")
    cv2.setMouseCallback("Arm Guidance", on_mouse)

    logger.info("=== Robot Arm Guidance: Red -> Yellow (USB control) ===")
    logger.info("  keys: l lock | d drop | g/G gripper cal | u unlock | r reset | q quit")

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                break

            state["frame"] = frame.copy()  # clean snapshot for template calibration
            scene.update(frame)
            scene.draw(frame)

            # Use the gripper tip for guidance; fall back to centroid.
            arm = scene.arm_gripper or scene.arm_center
            status = ""

            if mode == "SCAN":
                n = len(scene.balls_in_red)
                status = f"Balls on RED: {n} — press 'L' to lock"
            elif scene.red_box is None or scene.yellow_box is None:
                status = "Red/Yellow zones not detected"
                controller.stop()
            elif arm is None:
                status = "Blue arm not detected"
                controller.stop()
            else:
                if mode == "PICK":
                    target = scene.closest_pending_to(arm)
                    if target is None:
                        mode = "DONE"
                    else:
                        current_target_id = target["id"]
                        tx, ty = target["pos"]
                        dx, dy = tx - arm[0], ty - arm[1]
                        grip_dist = (dx * dx + dy * dy) ** 0.5
                        # Gripper already on the ball -> treat as held.
                        if grip_dist < HOLDING_RADIUS:
                            cv2.putText(frame, f"HOLDING ball#{target['id']}",
                                        (frame.shape[1] // 2 - 170, 40),
                                        cv2.FONT_HERSHEY_SIMPLEX, 1.0,
                                        (0, 255, 80), 3)
                            controller.grip()
                            mode = "DROP"
                        else:
                            reached, ndx, ndy = draw_guidance(
                                frame, arm, (tx, ty), f"PICK ball#{target['id']}")
                            if reached:
                                controller.grip()
                                mode = "DROP"
                            else:
                                controller.steer(ndx, ndy)
                elif mode == "DROP":
                    target_lb = next((lb for lb in scene.locked_balls
                                      if lb["id"] == current_target_id), None)
                    if target_lb is None or target_lb["status"] == "done" \
                            or scene.new_drop_detected():
                        if target_lb is not None and target_lb["status"] != "done":
                            scene.mark_done(current_target_id)
                        controller.release()
                        current_target_id = None
                        drop_hold_frames = 0
                        mode = "PICK"
                    else:
                        drop_pt = scene.yellow_drop_point()
                        if drop_pt is None:
                            status = "Lost yellow zone"
                            controller.stop()
                        else:
                            reached, ndx, ndy = draw_guidance(
                                frame, arm, drop_pt,
                                f"DROP ball#{current_target_id}")
                            if reached:
                                drop_hold_frames += 1
                                if drop_hold_frames > 30:
                                    controller.release()
                                    scene.mark_done(current_target_id)
                                    current_target_id = None
                                    drop_hold_frames = 0
                                    mode = "PICK"
                            else:
                                controller.steer(ndx, ndy)
                                drop_hold_frames = 0

            if mode == "DONE":
                controller.stop()

            # HUD
            cv2.putText(frame, f"MODE: {mode}", (10, 25),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
            link = "DRY-RUN" if controller.dry_run else "USB LINKED"
            cv2.putText(frame, link, (frame.shape[1] - 150, 25),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6,
                        (0, 165, 255) if controller.dry_run else (60, 200, 60), 2)
            if scene.locked:
                pend = len(scene.pending_locked())
                total = len(scene.locked_balls)
                cv2.putText(frame, f"locked: {pend}/{total} remaining",
                            (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.55,
                            (200, 200, 200), 2)
            else:
                cv2.putText(frame, f"detected on red: {len(scene.balls_in_red)}",
                            (10, 50), cv2.FONT_HERSHEY_SIMPLEX, 0.55,
                            (200, 200, 200), 2)

            if mode == "DONE":
                cv2.putText(frame, "ALL BALLS MOVED",
                            (frame.shape[1] // 2 - 140, frame.shape[0] // 2),
                            cv2.FONT_HERSHEY_SIMPLEX, 1.2, (0, 255, 80), 3)
            if status:
                cv2.putText(frame, status, (10, frame.shape[0] - 15),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 0, 220), 2)
            if calibrating_gripper["on"]:
                cv2.putText(frame, "Click on the GRIPPER",
                            (frame.shape[1] // 2 - 140, frame.shape[0] - 40),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)

            cv2.imshow("Arm Guidance", frame)

            key = cv2.waitKey(1) & 0xFF
            if key == ord("q"):
                break
            elif key == ord("l") and mode == "SCAN":
                if scene.balls_in_red:
                    scene.lock_current()
                    mode = "PICK"
                    logger.info("[Locked] %d balls", len(scene.locked_balls))
                else:
                    logger.info("Cannot lock: no balls detected on red side.")
            elif key == ord("g"):
                calibrating_gripper["on"] = True
                logger.info("Gripper calibration: click on the gripper in the window.")
            elif key == ord("G"):
                scene.clear_gripper_calibration()
                logger.info("Gripper calibration cleared (back to auto-detect).")
            elif key == ord("d") and current_target_id is not None:
                controller.release()
                scene.mark_done(current_target_id)
                current_target_id = None
                drop_hold_frames = 0
                mode = "PICK"
            elif key == ord("u"):
                scene.unlock()
                controller.stop()
                current_target_id = None
                drop_hold_frames = 0
                mode = "SCAN"
            elif key == ord("r"):
                scene.unlock()
                controller.stop()
                current_target_id = None
                drop_hold_frames = 0
                mode = "SCAN"
    finally:
        cap.release()
        cv2.destroyAllWindows()
        shutdown_controller(controller)

    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Camera-guided robotic-arm control over USB.")
    p.add_argument("--camera", type=int, default=0, help="camera index (default 0)")
    p.add_argument("--vid", type=lambda s: int(s, 0), default=DEFAULT_VID,
                   help="USB vendor id (default 0x1FC9)")
    p.add_argument("--pid", type=lambda s: int(s, 0), default=DEFAULT_PID,
                   help="USB product id (default 0xA2)")
    p.add_argument("--min-interval", type=float, default=0.06,
                   help="seconds between repeated identical MOVE commands")
    p.add_argument("--dry-run", action="store_true",
                   help="log arm commands instead of sending them over USB")
    return p.parse_args(argv)


def main(argv=None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
