"""SecureSession: ECDH handshake + AES-256-CBC + AES-256-CMAC over USB HID.

Takes an already-connected transport object (e.g. MCXN947_USB_Comm). The
transport must expose:
    write(data: bytes) -> int   # sends the 64-byte HID frame
    read(size: int = 64) -> bytes | None | sequence of ints  # returns up to `size` bytes; None on timeout

The session never touches the USB device directly.
"""
from __future__ import annotations

import logging
from enum import Enum, auto

from . import crypto, protocol

logger = logging.getLogger(__name__)


class SessionState(Enum):
    IDLE = auto()
    WAIT_MCU_PUBKEY = auto()
    WAIT_HANDSHAKE_DONE = auto()
    READY = auto()
    CLOSED = auto()


class SessionError(Exception):
    pass


class SecureSession:
    def __init__(self, comm) -> None:
        self._comm = comm
        self._state = SessionState.IDLE
        self._reassembler = protocol.Reassembler()
        self._priv = None
        self._k_cbc: bytes | None = None
        self._k_cmac: bytes | None = None

    @property
    def state(self) -> SessionState:
        return self._state

    def handshake(self) -> None:
        if self._state is not SessionState.IDLE:
            raise SessionError(f"handshake called in state {self._state.name}")

        logger.info("handshake: sending HELLO")
        self._send_message(protocol.MSG_HELLO, b"")

        self._state = SessionState.WAIT_MCU_PUBKEY
        logger.info("handshake: waiting for MCU_PUBKEY")
        mcu_pub_raw = self._recv_exact(protocol.MSG_MCU_PUBKEY)
        mcu_pub_raw = mcu_pub_raw[: crypto.PUBKEY_RAW_SIZE]

        logger.info("handshake: generating PC keypair and sending PC_PUBKEY")
        self._priv, pc_pub_raw = crypto.generate_ecdh_keypair()
        self._send_message(protocol.MSG_PC_PUBKEY, pc_pub_raw)

        logger.info("handshake: deriving shared secret + session keys")
        z = crypto.derive_shared_secret(self._priv, mcu_pub_raw)
        logger.info("DEBUG Z = %s", z.hex())
        self._k_cbc, self._k_cmac = crypto.derive_session_keys(z)
        logger.info("DEBUG K_CMAC = %s", self._k_cmac.hex())

        self._state = SessionState.WAIT_HANDSHAKE_DONE
        logger.info("handshake: waiting for HANDSHAKE_DONE")
        self._recv_exact(protocol.MSG_HANDSHAKE_DONE)

        self._state = SessionState.READY
        logger.info("handshake: channel ready")

    def send(self, plaintext: bytes) -> None:
        self._require_ready()
        record = crypto.encrypt(self._k_cbc, self._k_cmac, plaintext)
        # Prefix with 2-byte big-endian record length so the peer knows where
        # the ciphertext ends inside the padded frame payload.
        framed = len(record).to_bytes(2, "big") + record
        self._send_message(protocol.MSG_ENC_DATA, framed)

    def recv(self) -> bytes:
        self._require_ready()
        payload = self._recv_exact(protocol.MSG_ENC_DATA)
        if len(payload) < 2:
            raise SessionError("ENC_DATA payload too short for length prefix")
        n = int.from_bytes(payload[:2], "big")
        if n < 48 or 2 + n > len(payload):
            raise SessionError(f"ENC_DATA length field invalid: {n}")
        record = payload[2 : 2 + n]
        try:
            return crypto.decrypt(self._k_cbc, self._k_cmac, record)
        except crypto.CryptoError:
            self._state = SessionState.CLOSED
            self._safe_send(protocol.MSG_RESET, b"")
            raise

    def close(self) -> None:
        if self._state is not SessionState.CLOSED:
            self._safe_send(protocol.MSG_RESET, b"")
        self._state = SessionState.CLOSED
        self._priv = None
        self._k_cbc = None
        self._k_cmac = None
        self._reassembler.reset()

    def _require_ready(self) -> None:
        if self._state is not SessionState.READY:
            raise SessionError(f"operation requires READY, state is {self._state.name}")

    def _send_message(self, msg_type: int, payload: bytes) -> None:
        for frame in protocol.encode_frames(msg_type, payload):
            self._comm.write(frame)

    def _safe_send(self, msg_type: int, payload: bytes) -> None:
        try:
            self._send_message(msg_type, payload)
        except Exception as exc:
            logger.debug("swallowing send error during teardown: %s", exc)

    def _recv_exact(self, expected_type: int) -> bytes:
        """Read frames until a full logical message is reassembled. Raise if
        it isn't the expected type.
        """
        while True:
            frame = self._read_frame()
            try:
                result = self._reassembler.feed(frame)
            except protocol.ProtocolError as e:
                self._reassembler.reset()
                raise SessionError(f"framing error: {e}") from e
            if result is None:
                continue

            msg_type, payload = result
            if msg_type == expected_type:
                return payload
            if msg_type == protocol.MSG_ERROR:
                code = payload[0] if payload else 0
                raise SessionError(f"peer sent ERROR code {code:#x}")
            if msg_type == protocol.MSG_RESET:
                self._state = SessionState.CLOSED
                raise SessionError("peer sent RESET")
            raise SessionError(
                f"expected message type {expected_type:#x}, got {msg_type:#x}"
            )

    def _read_frame(self) -> bytes:
        raw = self._comm.read(protocol.FRAME_SIZE)
        if raw is None:
            raise SessionError("read timeout")
        data = bytes(raw)
        if len(data) != protocol.FRAME_SIZE:
            raise SessionError(
                f"short read: {len(data)}B, expected {protocol.FRAME_SIZE}B"
            )
        return data
