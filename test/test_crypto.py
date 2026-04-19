import pytest

from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.ciphers import algorithms

from security import crypto


class TestECDHAndKDF:
    def test_keypair_sizes(self):
        priv, raw_pub = crypto.generate_ecdh_keypair()
        assert len(raw_pub) == crypto.PUBKEY_RAW_SIZE
        # Round-trip the raw pubkey back to an EC key.
        assert crypto.public_key_from_raw(raw_pub) is not None

    def test_ecdh_produces_matching_secrets(self):
        a_priv, a_pub = crypto.generate_ecdh_keypair()
        b_priv, b_pub = crypto.generate_ecdh_keypair()
        z_ab = crypto.derive_shared_secret(a_priv, b_pub)
        z_ba = crypto.derive_shared_secret(b_priv, a_pub)
        assert z_ab == z_ba
        assert len(z_ab) == crypto.SHARED_SECRET_SIZE

    def test_session_keys_deterministic(self):
        z = bytes(range(32))
        k1_cbc, k1_cmac = crypto.derive_session_keys(z)
        k2_cbc, k2_cmac = crypto.derive_session_keys(z)
        assert k1_cbc == k2_cbc
        assert k1_cmac == k2_cmac
        assert len(k1_cbc) == crypto.AES_KEY_SIZE
        assert len(k1_cmac) == crypto.AES_KEY_SIZE
        assert k1_cbc != k1_cmac

    def test_session_keys_change_with_secret(self):
        z1 = bytes(range(32))
        z2 = bytes((i ^ 0xFF) for i in range(32))
        k1_cbc, k1_cmac = crypto.derive_session_keys(z1)
        k2_cbc, k2_cmac = crypto.derive_session_keys(z2)
        assert k1_cbc != k2_cbc
        assert k1_cmac != k2_cmac

    def test_session_keys_match_hkdf_sp80056c(self):
        """Pin the KDF to NIST SP800-56C one-step with SHA-256 so the MCU
        mcuxClEls_Hkdf_Sp80056c_Async output can be cross-checked."""
        import hashlib
        z = bytes(range(32))

        def hkdf_block(label):
            h = hashlib.sha256()
            h.update((1).to_bytes(4, "big"))
            h.update(z)
            h.update(label)
            return h.digest()

        expected_k_cbc  = hkdf_block(crypto.HKDF_LABEL_KCBC)
        expected_k_cmac = hkdf_block(crypto.HKDF_LABEL_KCMAC)

        k_cbc, k_cmac = crypto.derive_session_keys(z)
        assert k_cbc == expected_k_cbc
        assert k_cmac == expected_k_cmac

    def test_hkdf_labels_are_fixed_size(self):
        # Labels are held at HKDF_LABEL_SIZE for parity with the MCU-side
        # const arrays; both sides must agree exactly.
        for label in (crypto.HKDF_LABEL_KCBC, crypto.HKDF_LABEL_KCMAC):
            assert len(label) == crypto.HKDF_LABEL_SIZE

    def test_session_keys_wrong_secret_size_rejected(self):
        with pytest.raises(crypto.CryptoError):
            crypto.derive_session_keys(b"\x00" * 16)

    def test_invalid_pubkey_rejected(self):
        # Point not on curve.
        with pytest.raises(crypto.CryptoError):
            crypto.public_key_from_raw(b"\x00" * 64)

    def test_bad_pubkey_length_rejected(self):
        with pytest.raises(crypto.CryptoError):
            crypto.public_key_from_raw(b"\x00" * 32)


class TestEncryptDecryptRoundtrip:
    def setup_method(self):
        self.k_cbc = bytes(range(32))
        self.k_cmac = bytes(range(32, 64))

    def test_short_message(self):
        pt = b"fire motor 1 to 30 degrees"
        record = crypto.encrypt(self.k_cbc, self.k_cmac, pt)
        assert len(record) >= 48  # IV(16) + CT(>=16) + TAG(16)
        out = crypto.decrypt(self.k_cbc, self.k_cmac, record)
        assert out == pt

    def test_empty_message(self):
        record = crypto.encrypt(self.k_cbc, self.k_cmac, b"")
        # PKCS#7 pads empty to one full block.
        assert len(record) == 16 + 16 + 16
        out = crypto.decrypt(self.k_cbc, self.k_cmac, record)
        assert out == b""

    def test_exactly_one_block(self):
        pt = b"A" * 16
        record = crypto.encrypt(self.k_cbc, self.k_cmac, pt)
        # One block plaintext + one padding block = 2 CT blocks.
        assert len(record) == 16 + 32 + 16
        assert crypto.decrypt(self.k_cbc, self.k_cmac, record) == pt

    def test_large_message(self):
        pt = bytes(i & 0xFF for i in range(1000))
        record = crypto.encrypt(self.k_cbc, self.k_cmac, pt)
        assert crypto.decrypt(self.k_cbc, self.k_cmac, record) == pt

    def test_each_encryption_uses_fresh_iv(self):
        pt = b"same message"
        r1 = crypto.encrypt(self.k_cbc, self.k_cmac, pt)
        r2 = crypto.encrypt(self.k_cbc, self.k_cmac, pt)
        assert r1[:16] != r2[:16]
        assert r1 != r2


class TestTamperDetection:
    def setup_method(self):
        self.k_cbc = bytes(range(32))
        self.k_cmac = bytes(range(32, 64))
        self.pt = b"sensitive command payload"
        self.record = crypto.encrypt(self.k_cbc, self.k_cmac, self.pt)

    def test_flip_ciphertext_byte_rejected(self):
        iv = self.record[:16]
        ct = self.record[16:-16]
        tag = self.record[-16:]
        tampered_ct = bytearray(ct)
        tampered_ct[0] ^= 0x01
        bad = iv + bytes(tampered_ct) + tag
        with pytest.raises(crypto.CryptoError):
            crypto.decrypt(self.k_cbc, self.k_cmac, bad)

    def test_flip_iv_byte_rejected(self):
        bad = bytearray(self.record)
        bad[0] ^= 0x01
        with pytest.raises(crypto.CryptoError):
            crypto.decrypt(self.k_cbc, self.k_cmac, bytes(bad))

    def test_flip_tag_byte_rejected(self):
        bad = bytearray(self.record)
        bad[-1] ^= 0x01
        with pytest.raises(crypto.CryptoError):
            crypto.decrypt(self.k_cbc, self.k_cmac, bytes(bad))

    def test_wrong_cmac_key_rejected(self):
        wrong = bytes(32)
        with pytest.raises(crypto.CryptoError):
            crypto.decrypt(self.k_cbc, wrong, self.record)

    def test_truncated_record_rejected(self):
        with pytest.raises(crypto.CryptoError):
            crypto.decrypt(self.k_cbc, self.k_cmac, self.record[:30])
