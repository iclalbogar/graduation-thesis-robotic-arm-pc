"""HID frame format: 64-byte reports with a 3-byte header.

    Byte 0: type
    Byte 1: frame_idx  (0-based index within the logical message)
    Byte 2: frame_cnt  (total frames in the logical message, 1-255)
    Bytes 3..63: up to 61 bytes of payload (last frame zero-padded)

Logical messages are the concatenation of frame payloads 0..frame_cnt-1.
"""
from dataclasses import dataclass


FRAME_SIZE = 64
HEADER_SIZE = 3
PAYLOAD_PER_FRAME = FRAME_SIZE - HEADER_SIZE  # 61
MAX_FRAMES = 255
MAX_PAYLOAD = PAYLOAD_PER_FRAME * MAX_FRAMES


# Message types
MSG_HELLO = 0x01
MSG_PC_PUBKEY = 0x02
MSG_MCU_PUBKEY = 0x03
MSG_HANDSHAKE_DONE = 0x04
MSG_ENC_DATA = 0x10
MSG_RESET = 0xFE
MSG_ERROR = 0xFF


# Error codes carried inside an ERROR message payload
ERR_BAD_FRAME = 0x01
ERR_BAD_STATE = 0x02
ERR_ECDH_FAILED = 0x03
ERR_MAC_MISMATCH = 0x04
ERR_DECRYPT_FAILED = 0x05


class ProtocolError(Exception):
    pass


def encode_frames(msg_type: int, payload: bytes) -> list[bytes]:
    """Split a logical message into a list of 64-byte HID frames."""
    if not 0 <= msg_type <= 0xFF:
        raise ProtocolError(f"type out of range: {msg_type}")
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError(f"payload {len(payload)}B exceeds max {MAX_PAYLOAD}B")

    if len(payload) == 0:
        return [bytes([msg_type, 0, 1]) + b"\x00" * PAYLOAD_PER_FRAME]

    frame_cnt = (len(payload) + PAYLOAD_PER_FRAME - 1) // PAYLOAD_PER_FRAME
    frames = []
    for idx in range(frame_cnt):
        chunk = payload[idx * PAYLOAD_PER_FRAME:(idx + 1) * PAYLOAD_PER_FRAME]
        chunk = chunk.ljust(PAYLOAD_PER_FRAME, b"\x00")
        frames.append(bytes([msg_type, idx, frame_cnt]) + chunk)
    return frames


@dataclass
class Frame:
    type: int
    idx: int
    cnt: int
    payload: bytes  # raw 61-byte chunk (possibly padded)


def decode_frame(frame: bytes) -> Frame:
    if len(frame) != FRAME_SIZE:
        raise ProtocolError(f"frame must be {FRAME_SIZE}B, got {len(frame)}B")
    t, idx, cnt = frame[0], frame[1], frame[2]
    if cnt == 0:
        raise ProtocolError("frame_cnt must be >= 1")
    if idx >= cnt:
        raise ProtocolError(f"frame_idx {idx} >= frame_cnt {cnt}")
    return Frame(type=t, idx=idx, cnt=cnt, payload=frame[HEADER_SIZE:])


class Reassembler:
    """Accumulates frames of a single in-progress logical message.

    Call feed(frame_bytes); when a message completes, feed() returns
    (msg_type, payload) and the internal buffer is reset. Returns None while
    more frames are expected.
    """

    def __init__(self) -> None:
        self._type: int | None = None
        self._cnt: int = 0
        self._next_idx: int = 0
        self._chunks: list[bytes] = []

    def reset(self) -> None:
        self._type = None
        self._cnt = 0
        self._next_idx = 0
        self._chunks = []

    def feed(self, frame_bytes: bytes) -> tuple[int, bytes] | None:
        f = decode_frame(frame_bytes)

        if self._type is None:
            if f.idx != 0:
                raise ProtocolError(f"expected frame_idx=0, got {f.idx}")
            self._type = f.type
            self._cnt = f.cnt
            self._next_idx = 0
            self._chunks = []
        else:
            if f.type != self._type:
                raise ProtocolError(
                    f"type changed mid-message: {self._type:#x} -> {f.type:#x}"
                )
            if f.cnt != self._cnt:
                raise ProtocolError(
                    f"frame_cnt changed mid-message: {self._cnt} -> {f.cnt}"
                )
            if f.idx != self._next_idx:
                raise ProtocolError(
                    f"out-of-order frame: expected {self._next_idx}, got {f.idx}"
                )

        self._chunks.append(f.payload)
        self._next_idx += 1

        if self._next_idx == self._cnt:
            msg_type = self._type
            # Last frame is zero-padded; callers that need exact length must
            # either encode the length in the payload or use a format (like
            # ENC_DATA) whose structure is self-describing.
            payload = b"".join(self._chunks)
            self.reset()
            return msg_type, payload
        return None
