import cv2
import numpy as np
from collections import deque

# HSV ranges tuned for the table setup:
#   - black background, red + yellow paper sides, blue 3D-printed arm, white balls.

# White balls: low saturation, high value.
WHITE_LOWER = np.array([0,   0, 200])
WHITE_UPPER = np.array([179, 50, 255])

# Red wraps around hue=0, so two sub-ranges.
RED_LOWER_1 = np.array([0,   110, 70])
RED_UPPER_1 = np.array([10,  255, 255])
RED_LOWER_2 = np.array([170, 110, 70])
RED_UPPER_2 = np.array([179, 255, 255])

# Yellow paper.
YELLOW_LOWER = np.array([15, 40, 140])
YELLOW_UPPER = np.array([40, 255, 255])

# Blue 3D-printed arm.
BLUE_LOWER = np.array([95,  120, 60])
BLUE_UPPER = np.array([130, 255, 255])


def _largest_contour(mask, min_area):
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None
    largest = max(contours, key=cv2.contourArea)
    if cv2.contourArea(largest) < min_area:
        return None
    return largest


def _clean(mask, k=5, iters=2):
    kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k, k))
    mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN,  kernel, iterations=1)
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, kernel, iterations=iters)
    return mask


def _skeletonize(mask):
    """Morphological skeleton. Returns a uint8 image (0 / 255)."""
    skel = np.zeros_like(mask)
    img = mask.copy()
    elem = cv2.getStructuringElement(cv2.MORPH_CROSS, (3, 3))
    # Cap iterations so a stray fat blob can't hang the loop.
    for _ in range(200):
        opened = cv2.morphologyEx(img, cv2.MORPH_OPEN, elem)
        temp = cv2.subtract(img, opened)
        eroded = cv2.erode(img, elem)
        skel = cv2.bitwise_or(skel, temp)
        img = eroded
        if cv2.countNonZero(img) == 0:
            break
    return skel


# 8-neighbour counting kernel for endpoint detection (center weighted 10).
_NEIGHBOR_KERNEL = np.array([[1, 1, 1],
                             [1, 10, 1],
                             [1, 1, 1]], dtype=np.uint8)


def _skeleton_endpoints(skel):
    """Return list of (x, y) endpoints (skeleton pixels with exactly 1 neighbour)."""
    sk = (skel > 0).astype(np.uint8)
    filt = cv2.filter2D(sk, -1, _NEIGHBOR_KERNEL)
    # center==1 contributes 10, each neighbour contributes 1 → 11 = endpoint.
    ys, xs = np.where(filt == 11)
    return list(zip(xs.tolist(), ys.tolist()))


def _farthest_geodesic(skel, start_xy):
    """BFS along the skeleton from start; return point with the largest hop distance."""
    sk = (skel > 0)
    H, W = sk.shape
    dist = -np.ones((H, W), dtype=np.int32)
    sx, sy = start_xy
    if not (0 <= sx < W and 0 <= sy < H and sk[sy, sx]):
        return None, 0
    dist[sy, sx] = 0
    q = deque([(sx, sy)])
    best = (sx, sy)
    best_d = 0
    while q:
        x, y = q.popleft()
        d = dist[y, x]
        if d > best_d:
            best_d = d
            best = (x, y)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if dx == 0 and dy == 0:
                    continue
                nx, ny = x + dx, y + dy
                if 0 <= nx < W and 0 <= ny < H and sk[ny, nx] and dist[ny, nx] < 0:
                    dist[ny, nx] = d + 1
                    q.append((nx, ny))
    return best, best_d


class SceneTracker:
    """Detects red zone, yellow zone, blue arm tip, and white balls per zone."""

    def __init__(self):
        self.red_box    = None   # (x,y,w,h)
        self.yellow_box = None
        self.arm_center  = None  # centroid of the blue mass (base area)
        self.arm_gripper = None  # gripper tip (auto-detected OR template-tracked)
        # Template tracking — set by calibrate_gripper(); drives arm_gripper.
        self._gripper_template = None
        self._gripper_last = None
        self._gripper_search_radius = 90
        self.gripper_conf = 0.0
        self.balls_in_red    = []   # list of (cx, cy, radius)
        self.balls_in_yellow = []
        self.all_balls       = []   # every detected white ball, regardless of zone

        # Locked-ball tracking
        self.locked = False
        # Each item: {"id", "pos": (x,y), "r", "status": "pending"|"done", "miss": int}
        self.locked_balls = []
        self._match_radius = 90
        self._yellow_baseline = 0  # # of yellow balls at lock time

    # ---------- zone detection ----------
    def _detect_zones(self, hsv):
        red_mask = cv2.inRange(hsv, RED_LOWER_1, RED_UPPER_1) | \
                   cv2.inRange(hsv, RED_LOWER_2, RED_UPPER_2)
        yellow_mask = cv2.inRange(hsv, YELLOW_LOWER, YELLOW_UPPER)
        red_mask    = _clean(red_mask, k=7, iters=2)
        yellow_mask = _clean(yellow_mask, k=7, iters=2)

        red_c    = _largest_contour(red_mask,    min_area=3000)
        yellow_c = _largest_contour(yellow_mask, min_area=3000)

        self.red_box    = cv2.boundingRect(red_c)    if red_c    is not None else None
        self.yellow_box = cv2.boundingRect(yellow_c) if yellow_c is not None else None
        return red_mask, yellow_mask

    # ---------- arm detection ----------
    def _detect_arm(self, hsv):
        blue_mask = cv2.inRange(hsv, BLUE_LOWER, BLUE_UPPER)
        # Aggressive cleaning so wires / specular highlights don't survive.
        blue_mask = _clean(blue_mask, k=7, iters=3)
        arm_c = _largest_contour(blue_mask, min_area=2000)
        if arm_c is None:
            self.arm_center = None
            self.arm_gripper = None
            return blue_mask
        M = cv2.moments(arm_c)
        if M["m00"] == 0:
            self.arm_center = None
            self.arm_gripper = None
            return blue_mask

        cx_arm = int(M["m10"] / M["m00"])
        cy_arm = int(M["m01"] / M["m00"])
        self.arm_center = (cx_arm, cy_arm)

        # If the user has calibrated the gripper, the template tracker drives
        # arm_gripper from the colour frame — skip the (expensive) skeleton.
        if self._gripper_template is not None:
            return blue_mask

        # Gripper-tip estimate — skeleton-based:
        #   1. Build an arm-only mask (largest contour filled).
        #   2. Skeletonize it (medial axis).
        #   3. Find all skeleton endpoints.
        #   4. Pick the base endpoint = endpoint closest to the bbox bottom-center.
        #   5. BFS along the skeleton from the base endpoint; the farthest
        #      skeleton pixel (by hop count) is the gripper tip.
        # This follows the kinematic chain instead of straight-line distance, so
        # the elbow corner can't masquerade as the gripper.
        x, y, w, h = cv2.boundingRect(arm_c)
        base_x = x + w // 2
        base_y = y + h - 1  # inside the bbox

        arm_only = np.zeros_like(blue_mask)
        cv2.drawContours(arm_only, [arm_c], -1, 255, thickness=cv2.FILLED)

        # Downsample for speed — skeletonization is O(image).
        scale = 0.5
        small = cv2.resize(arm_only, (0, 0), fx=scale, fy=scale,
                           interpolation=cv2.INTER_NEAREST)
        skel = _skeletonize(small)
        endpoints = _skeleton_endpoints(skel)

        self.arm_gripper = None
        if endpoints:
            sbx, sby = int(base_x * scale), int(base_y * scale)
            # Base endpoint: closest skeleton endpoint to the bbox base.
            base_ep = min(endpoints,
                          key=lambda p: (p[0] - sbx) ** 2 + (p[1] - sby) ** 2)
            tip, hops = _farthest_geodesic(skel, base_ep)
            if tip is not None and hops > 5:
                self.arm_gripper = (int(tip[0] / scale), int(tip[1] / scale))

        # Fallback if skeleton was degenerate.
        if self.arm_gripper is None:
            self.arm_gripper = self.arm_center

        return blue_mask

    # ---------- ball detection ----------
    def _detect_balls(self, hsv, red_mask, yellow_mask):
        white_mask = cv2.inRange(hsv, WHITE_LOWER, WHITE_UPPER)
        white_mask = _clean(white_mask, k=5, iters=1)

        contours, _ = cv2.findContours(white_mask, cv2.RETR_EXTERNAL,
                                       cv2.CHAIN_APPROX_SIMPLE)
        self.balls_in_red.clear()
        self.balls_in_yellow.clear()
        self.all_balls.clear()

        for c in contours:
            area = cv2.contourArea(c)
            if area < 150 or area > 8000:
                continue
            (x, y), r = cv2.minEnclosingCircle(c)
            cx, cy, r = int(x), int(y), int(r)
            if r < 6:
                continue
            # circularity filter: balls are round
            perim = cv2.arcLength(c, True)
            if perim == 0:
                continue
            circularity = 4 * np.pi * area / (perim * perim)
            if circularity < 0.55:
                continue
            self.all_balls.append((cx, cy, r))
            # Classify by which zone mask the center sits in.
            in_red = in_yellow = False
            if 0 <= cy < red_mask.shape[0] and 0 <= cx < red_mask.shape[1]:
                in_red    = bool(red_mask[cy, cx])
                in_yellow = bool(yellow_mask[cy, cx])
            if not (in_red or in_yellow):
                # Fall back to bounding-box test for balls near paper edge / arm shadow.
                if self.red_box and _inside_box(cx, cy, self.red_box):
                    in_red = True
                elif self.yellow_box and _inside_box(cx, cy, self.yellow_box):
                    in_yellow = True
            if in_red:
                self.balls_in_red.append((cx, cy, r))
            elif in_yellow:
                self.balls_in_yellow.append((cx, cy, r))

        return white_mask

    def update(self, frame):
        hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
        red_mask, yellow_mask = self._detect_zones(hsv)
        self._detect_arm(hsv)
        self._track_gripper(frame)
        self._detect_balls(hsv, red_mask, yellow_mask)
        if self.locked:
            self._update_locked()

    # ---------- gripper calibration ----------
    def calibrate_gripper(self, frame, click_x, click_y, half=16):
        """Snapshot a patch around the click and use it as the gripper template."""
        H, W = frame.shape[:2]
        x0 = max(0, click_x - half); x1 = min(W, click_x + half + 1)
        y0 = max(0, click_y - half); y1 = min(H, click_y + half + 1)
        if x1 - x0 < 6 or y1 - y0 < 6:
            return False
        self._gripper_template = frame[y0:y1, x0:x1].copy()
        self._gripper_last = (click_x, click_y)
        self.arm_gripper = (click_x, click_y)
        self.gripper_conf = 1.0
        return True

    def clear_gripper_calibration(self):
        self._gripper_template = None
        self._gripper_last = None
        self.gripper_conf = 0.0

    def _track_gripper(self, frame):
        """Template-match the gripper inside a small window around its last
        known position. Updates arm_gripper if confidence is high enough."""
        if self._gripper_template is None or self._gripper_last is None:
            return
        H, W = frame.shape[:2]
        th, tw = self._gripper_template.shape[:2]
        lx, ly = self._gripper_last
        sw = self._gripper_search_radius
        x0 = max(0, lx - sw)
        y0 = max(0, ly - sw)
        x1 = min(W, lx + sw + tw)
        y1 = min(H, ly + sw + th)
        roi = frame[y0:y1, x0:x1]
        if roi.shape[0] < th or roi.shape[1] < tw:
            return
        res = cv2.matchTemplate(roi, self._gripper_template, cv2.TM_CCOEFF_NORMED)
        _, max_val, _, max_loc = cv2.minMaxLoc(res)
        self.gripper_conf = float(max_val)
        if max_val > 0.45:
            nx = x0 + max_loc[0] + tw // 2
            ny = y0 + max_loc[1] + th // 2
            self._gripper_last = (nx, ny)
            self.arm_gripper = (nx, ny)
        # On low confidence we keep the last known gripper position (coasting).

    # ---------- locking / tracking ----------
    def lock_current(self):
        """Snapshot current red-zone balls as the fixed working set (IDs 1..N)."""
        self.locked_balls = [
            {"id": i, "pos": (cx, cy), "r": r, "status": "pending", "miss": 0}
            for i, (cx, cy, r) in enumerate(self.balls_in_red, start=1)
        ]
        self._yellow_baseline = len(self.balls_in_yellow)
        self.locked = True

    def delivered_count(self):
        """How many balls now appear on the yellow side beyond the lock-time baseline."""
        return max(0, len(self.balls_in_yellow) - self._yellow_baseline)

    def done_count(self):
        return sum(1 for lb in self.locked_balls if lb["status"] == "done")

    def new_drop_detected(self):
        """True if a ball arrived in yellow that hasn't been accounted for yet."""
        return self.delivered_count() > self.done_count()

    def unlock(self):
        self.locked = False
        self.locked_balls = []

    def _update_locked(self):
        """Match every locked ball (including ones already marked done) to the
        nearest detected white ball, and refresh status from current zone."""
        used = set()
        for lb in self.locked_balls:
            lx, ly = lb["pos"]
            best, best_d = None, self._match_radius ** 2
            for j, (cx, cy, _r) in enumerate(self.all_balls):
                if j in used:
                    continue
                d = (cx - lx) ** 2 + (cy - ly) ** 2
                if d < best_d:
                    best, best_d = j, d
            if best is not None:
                cx, cy, r = self.all_balls[best]
                lb["pos"] = (cx, cy)
                lb["r"] = r
                lb["miss"] = 0
                used.add(best)
            else:
                lb["miss"] += 1

            # Status follows current zone. Only flip status when we have a
            # fresh detection — if we're coasting on a stale position, leave
            # the previous status alone.
            if lb["miss"] == 0 and self.yellow_box is not None:
                in_yellow = _inside_box(lb["pos"][0], lb["pos"][1], self.yellow_box)
                if in_yellow:
                    lb["status"] = "done"
                elif lb["status"] == "done":
                    lb["status"] = "pending"

    def pending_locked(self):
        return [lb for lb in self.locked_balls if lb["status"] == "pending"]

    def closest_pending_to(self, point):
        pend = self.pending_locked()
        if not pend or point is None:
            return None
        px, py = point
        return min(pend, key=lambda lb: (lb["pos"][0] - px) ** 2
                                       + (lb["pos"][1] - py) ** 2)

    def mark_done(self, ball_id):
        for lb in self.locked_balls:
            if lb["id"] == ball_id:
                lb["status"] = "done"
                return

    # ---------- helpers ----------
    def yellow_drop_point(self):
        if self.yellow_box is None:
            return None
        x, y, w, h = self.yellow_box
        return (x + w // 2, y + h // 2)

    def closest_red_ball_to(self, point):
        if not self.balls_in_red or point is None:
            return None
        px, py = point
        return min(self.balls_in_red,
                   key=lambda b: (b[0] - px) ** 2 + (b[1] - py) ** 2)

    def draw(self, frame):
        if self.red_box is not None:
            x, y, w, h = self.red_box
            cv2.rectangle(frame, (x, y), (x + w, y + h), (60, 60, 220), 2)
            cv2.putText(frame, "RED ZONE", (x + 4, y + 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.55, (60, 60, 220), 2)
        if self.yellow_box is not None:
            x, y, w, h = self.yellow_box
            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 220, 220), 2)
            cv2.putText(frame, "YELLOW ZONE", (x + 4, y + 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 220, 220), 2)

        if not self.locked:
            for cx, cy, r in self.balls_in_red:
                cv2.circle(frame, (cx, cy), r, (60, 60, 220), 2)
                cv2.circle(frame, (cx, cy), 3, (60, 60, 220), -1)
            for cx, cy, r in self.balls_in_yellow:
                cv2.circle(frame, (cx, cy), r, (0, 220, 220), 2)
                cv2.circle(frame, (cx, cy), 3, (0, 220, 220), -1)
        else:
            for lb in self.locked_balls:
                cx, cy = lb["pos"]
                r = max(10, lb["r"])
                if lb["status"] == "done":
                    color = (120, 120, 120)
                elif lb["miss"] > 0:
                    color = (0, 165, 255)  # orange = coasting on last pos
                else:
                    color = (60, 200, 60)
                cv2.circle(frame, (cx, cy), r, color, 2)
                cv2.circle(frame, (cx, cy), 3, color, -1)
                tag = f"ball#{lb['id']}"
                if lb["status"] == "done":
                    tag += " (done)"
                cv2.putText(frame, tag, (cx - 25, cy - r - 6),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

        if self.arm_center is not None:
            cv2.circle(frame, self.arm_center, 8, (255, 80, 80), 1)
            cv2.putText(frame, "arm", (self.arm_center[0] + 10,
                                       self.arm_center[1] - 6),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 80, 80), 1)
        if self.arm_gripper is not None:
            cv2.drawMarker(frame, self.arm_gripper, (255, 80, 255),
                           cv2.MARKER_CROSS, 18, 2)
            tag = "GRIPPER"
            if self._gripper_template is not None:
                tag += f" ({self.gripper_conf:.2f})"
            cv2.putText(frame, tag,
                        (self.arm_gripper[0] + 10, self.arm_gripper[1] - 8),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 80, 255), 2)


def _inside_box(x, y, box):
    bx, by, bw, bh = box
    return bx <= x <= bx + bw and by <= y <= by + bh
