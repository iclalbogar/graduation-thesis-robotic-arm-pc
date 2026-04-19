"""End-to-end SecureSession test against a pure-Python fake MCU peer.

The fake uses the same `crypto` / `protocol` modules as the real PC side but
plays the MCU's role: receive HELLO, send MCU_PUBKEY, receive PC_PUBKEY, send
HANDSHAKE_DONE, then echo any encrypted payloads back.
"""
from __future__ import annotations

from collections import deque

import pytest

from security import crypto, protocol
from security.session import SecureSession, SessionError, SessionState


class FakeMcu:
    """Plays the MCU side of the handshake + echo. Consumes frames fed in and
    emits frames when there is a response."""

    def __init__(self) -> None:
        self._reassembler = protocol.Reassembler()
        self._priv = None
        self._k_cbc: bytes | None = None
        self._k_cmac: bytes | None = None
        self._state = "idle"

    def handle_frame(self, frame: bytes) -> list[bytes]:
        """Returns any frames the MCU wants to send in response."""
        result = self._reassembler.feed(frame)
        if result is None:
            return []
        msg_type, payload = result
        return self._dispatch(msg_type, payload)

    def _dispatch(self, msg_type: int, payload: bytes) -> list[bytes]:
        if msg_type == protocol.MSG_HELLO and self._state == "idle":
            self._priv, raw_pub = crypto.generate_ecdh_keypair()
            self._state = "wait_pc_pubkey"
            return protocol.encode_frames(protocol.MSG_MCU_PUBKEY, raw_pub)

        if msg_type == protocol.MSG_PC_PUBKEY and self._state == "wait_pc_pubkey":
            pc_pub_raw = payload[: crypto.PUBKEY_RAW_SIZE]
            z = crypto.derive_shared_secret(self._priv, pc_pub_raw)
            self._k_cbc, self._k_cmac = crypto.derive_session_keys(z)
            self._state = "ready"
            return protocol.encode_frames(protocol.MSG_HANDSHAKE_DONE, b"")

        if msg_type == protocol.MSG_ENC_DATA and self._state == "ready":
            # Peel the 2-byte length prefix the PC prepended so we can skip
            # the frame's zero-padding.
            n = int.from_bytes(payload[:2], "big")
            record = payload[2 : 2 + n]
            plaintext = crypto.decrypt(self._k_cbc, self._k_cmac, record)
            reply = crypto.encrypt(self._k_cbc, self._k_cmac, plaintext)
            framed = len(reply).to_bytes(2, "big") + reply
            return protocol.encode_frames(protocol.MSG_ENC_DATA, framed)

        if msg_type == protocol.MSG_RESET:
            self._state = "idle"
            return []

        return protocol.encode_frames(protocol.MSG_ERROR, bytes([protocol.ERR_BAD_STATE]))


class MockTransport:
    """Byte-for-byte stand-in for MCXN947_USB_Comm.write/read. Pairs the PC
    SecureSession with a FakeMcu by piping frames in both directions."""

    def __init__(self, mcu: FakeMcu) -> None:
        self._mcu = mcu
        self._mcu_tx: deque[bytes] = deque()

    def write(self, data) -> int:
        payload = bytes(data)
        for reply in self._mcu.handle_frame(payload):
            self._mcu_tx.append(reply)
        return len(payload)

    def read(self, size: int = 64):
        if not self._mcu_tx:
            return None
        return self._mcu_tx.popleft()


class TestFullHandshakeAndEcho:
    def test_handshake_completes(self):
        s = SecureSession(MockTransport(FakeMcu()))
        s.handshake()
        assert s.state is SessionState.READY

    def test_encrypted_echo(self):
        s = SecureSession(MockTransport(FakeMcu()))
        s.handshake()

        for pt in [b"hello", b"", b"A" * 48, bytes(range(100))]:
            s.send(pt)
            assert s.recv() == pt

    def test_cannot_send_before_handshake(self):
        s = SecureSession(MockTransport(FakeMcu()))
        with pytest.raises(SessionError):
            s.send(b"data")

    def test_cannot_double_handshake(self):
        s = SecureSession(MockTransport(FakeMcu()))
        s.handshake()
        with pytest.raises(SessionError):
            s.handshake()

    def test_close_tears_down(self):
        s = SecureSession(MockTransport(FakeMcu()))
        s.handshake()
        s.close()
        assert s.state is SessionState.CLOSED
        with pytest.raises(SessionError):
            s.send(b"x")


class TestErrorPaths:
    def test_peer_error_message_raises(self):
        # Build a transport that replies to HELLO with an ERROR frame.
        class AngryMcu:
            def handle_frame(self, _frame):
                return protocol.encode_frames(protocol.MSG_ERROR, bytes([protocol.ERR_BAD_STATE]))

        s = SecureSession(MockTransport(AngryMcu()))
        with pytest.raises(SessionError, match="ERROR"):
            s.handshake()

    def test_peer_reset_raises(self):
        class ResettingMcu:
            def handle_frame(self, _frame):
                return protocol.encode_frames(protocol.MSG_RESET, b"")

        s = SecureSession(MockTransport(ResettingMcu()))
        with pytest.raises(SessionError, match="RESET"):
            s.handshake()

    def test_read_timeout_surfaces_as_session_error(self):
        class SilentTransport:
            def write(self, data):
                return len(bytes(data))

            def read(self, size=64):
                return None

        s = SecureSession(SilentTransport())
        with pytest.raises(SessionError, match="timeout"):
            s.handshake()
