import pytest

from security import protocol


class TestFrameEncoding:
    def test_empty_payload_single_frame(self):
        frames = protocol.encode_frames(protocol.MSG_HELLO, b"")
        assert len(frames) == 1
        assert len(frames[0]) == protocol.FRAME_SIZE
        assert frames[0][0] == protocol.MSG_HELLO
        assert frames[0][1] == 0  # frame_idx
        assert frames[0][2] == 1  # frame_cnt
        assert frames[0][3:] == b"\x00" * protocol.PAYLOAD_PER_FRAME

    def test_short_payload_fits_one_frame(self):
        pt = b"hello"
        frames = protocol.encode_frames(protocol.MSG_ENC_DATA, pt)
        assert len(frames) == 1
        assert frames[0][0] == protocol.MSG_ENC_DATA
        assert frames[0][2] == 1
        assert frames[0][3 : 3 + len(pt)] == pt

    def test_exactly_one_frame_payload(self):
        pt = b"A" * protocol.PAYLOAD_PER_FRAME  # 61 bytes
        frames = protocol.encode_frames(protocol.MSG_ENC_DATA, pt)
        assert len(frames) == 1
        assert frames[0][3:] == pt

    def test_ecdh_pubkey_spans_two_frames(self):
        pubkey = bytes(range(64))
        frames = protocol.encode_frames(protocol.MSG_PC_PUBKEY, pubkey)
        assert len(frames) == 2
        assert frames[0][1] == 0 and frames[0][2] == 2
        assert frames[1][1] == 1 and frames[1][2] == 2
        assert frames[0][3:] == pubkey[:61]
        assert frames[1][3 : 3 + 3] == pubkey[61:]
        # Tail of last frame zero-padded.
        assert frames[1][3 + 3 :] == b"\x00" * (protocol.PAYLOAD_PER_FRAME - 3)

    def test_multi_frame_message(self):
        pt = bytes(i & 0xFF for i in range(500))
        frames = protocol.encode_frames(protocol.MSG_ENC_DATA, pt)
        expected_frames = (500 + protocol.PAYLOAD_PER_FRAME - 1) // protocol.PAYLOAD_PER_FRAME
        assert len(frames) == expected_frames

    def test_rejects_oversized_payload(self):
        with pytest.raises(protocol.ProtocolError):
            protocol.encode_frames(protocol.MSG_ENC_DATA, b"x" * (protocol.MAX_PAYLOAD + 1))

    def test_rejects_bad_type(self):
        with pytest.raises(protocol.ProtocolError):
            protocol.encode_frames(-1, b"")
        with pytest.raises(protocol.ProtocolError):
            protocol.encode_frames(0x100, b"")


class TestReassembly:
    def test_single_frame_roundtrip(self):
        pt = b"short message"
        frames = protocol.encode_frames(protocol.MSG_ENC_DATA, pt)
        r = protocol.Reassembler()
        result = r.feed(frames[0])
        assert result is not None
        mt, payload = result
        assert mt == protocol.MSG_ENC_DATA
        # The reassembled payload is padded to frame boundary; callers peel
        # their own length. First bytes must match.
        assert payload.startswith(pt)

    def test_multi_frame_roundtrip(self):
        pt = bytes(range(200))
        frames = protocol.encode_frames(protocol.MSG_PC_PUBKEY, pt)
        r = protocol.Reassembler()
        for f in frames[:-1]:
            assert r.feed(f) is None
        final = r.feed(frames[-1])
        assert final is not None
        mt, payload = final
        assert mt == protocol.MSG_PC_PUBKEY
        assert payload.startswith(pt)

    def test_reset_clears_state(self):
        frames = protocol.encode_frames(protocol.MSG_PC_PUBKEY, b"A" * 200)
        r = protocol.Reassembler()
        r.feed(frames[0])
        r.reset()
        # After reset, it expects a fresh message starting at idx 0.
        assert r._type is None

    def test_two_messages_back_to_back(self):
        fa = protocol.encode_frames(protocol.MSG_HELLO, b"")
        fb = protocol.encode_frames(protocol.MSG_ENC_DATA, b"hello")
        r = protocol.Reassembler()
        a = r.feed(fa[0])
        assert a[0] == protocol.MSG_HELLO
        b = r.feed(fb[0])
        assert b[0] == protocol.MSG_ENC_DATA

    def test_type_change_mid_message_raises(self):
        # Craft inconsistent frames manually.
        f0 = bytes([protocol.MSG_PC_PUBKEY, 0, 2]) + b"\x00" * 61
        f1 = bytes([protocol.MSG_MCU_PUBKEY, 1, 2]) + b"\x00" * 61
        r = protocol.Reassembler()
        r.feed(f0)
        with pytest.raises(protocol.ProtocolError):
            r.feed(f1)

    def test_out_of_order_raises(self):
        f0 = bytes([protocol.MSG_PC_PUBKEY, 0, 2]) + b"\x00" * 61
        f_skip = bytes([protocol.MSG_PC_PUBKEY, 2, 2]) + b"\x00" * 61  # gap
        r = protocol.Reassembler()
        r.feed(f0)
        with pytest.raises(protocol.ProtocolError):
            r.feed(f_skip)

    def test_first_frame_must_be_idx_zero(self):
        f1 = bytes([protocol.MSG_PC_PUBKEY, 1, 2]) + b"\x00" * 61
        r = protocol.Reassembler()
        with pytest.raises(protocol.ProtocolError):
            r.feed(f1)

    def test_frame_size_validated(self):
        with pytest.raises(protocol.ProtocolError):
            protocol.decode_frame(b"\x00" * 63)

    def test_frame_cnt_zero_rejected(self):
        bad = bytes([protocol.MSG_HELLO, 0, 0]) + b"\x00" * 61
        with pytest.raises(protocol.ProtocolError):
            protocol.decode_frame(bad)
