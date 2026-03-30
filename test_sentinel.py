"""
tests/test_sentinel.py — SentinelVault pytest suite
Author: Ridhaant Ajoy Thackur
"""
import os, sys, secrets, hashlib, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from sentinel_vault import (
    SentinelVault, TamperEvidentAuditLog, AuditEventType,
    PasswordManager, AES256GCMVault, TOTPEngine, JWTEngine,
    CryptoWalletEngine, ShamirSecretSharing, ThreatDetectionEngine,
    _HAS_CRYPTO, _HAS_ARGON2, _HAS_PYOTP, _HAS_JWT,
    VaultResult,
)


# ── Audit Log ─────────────────────────────────────────────────────────────────

class TestAuditLog:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.tmp.close()
        self.log = TamperEvidentAuditLog(self.tmp.name)

    def teardown_method(self):
        os.unlink(self.tmp.name)

    def test_empty_chain_valid(self):
        assert self.log.verify_chain().ok

    def test_chain_grows_valid(self):
        for i in range(10):
            self.log.append(AuditEventType.AUTH, f"user{i}", f"action{i}", {})
        result = self.log.verify_chain()
        assert result.ok
        assert result.data["entries"] == 10

    def test_tamper_detected(self):
        self.log.append(AuditEventType.AUTH, "alice", "login", {"ip": "1.2.3.4"})
        # Corrupt the file
        with open(self.tmp.name, "r+") as f:
            content = f.read()
            f.seek(0)
            f.write(content.replace('"actor":"alice"', '"actor":"mallory"'))
            f.truncate()
        result = self.log.verify_chain()
        assert not result.ok

    def test_hash_linkage(self):
        h1 = self.log.append(AuditEventType.CRYPTO, "u", "op1", {})
        h2 = self.log.append(AuditEventType.CRYPTO, "u", "op2", {})
        assert h1 != h2
        assert len(h1) == 64  # SHA-256 hex


# ── Password Manager ─────────────────────────────────────────────────────────

class TestPasswordManager:
    def setup_method(self):
        self.pm = PasswordManager()

    def test_hash_and_verify(self):
        pw = "C0rrectH0rse#BatteryStaple"
        h = self.pm.hash_password(pw)
        assert h.ok
        assert self.pm.verify_password(pw, h.data).ok

    def test_wrong_password_fails(self):
        h = self.pm.hash_password("right")
        assert h.ok
        assert not self.pm.verify_password("wrong", h.data).ok

    def test_generate_password_complexity(self):
        pw = PasswordManager.generate_secure_password(20)
        assert len(pw) == 20
        assert any(c.isupper() for c in pw)
        assert any(c.islower() for c in pw)
        assert any(c.isdigit() for c in pw)
        assert any(not c.isalnum() for c in pw)

    def test_unique_hashes(self):
        h1 = self.pm.hash_password("same")
        h2 = self.pm.hash_password("same")
        assert h1.data != h2.data  # different salts


# ── AES-256-GCM ──────────────────────────────────────────────────────────────

@pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
class TestAESVault:
    def setup_method(self):
        self.aes = AES256GCMVault()

    def test_roundtrip(self):
        msg = b"Hello AES-256-GCM"
        enc = self.aes.encrypt(msg, "secret")
        assert enc.ok
        dec = self.aes.decrypt(enc.data, "secret")
        assert dec.ok and dec.data == msg

    def test_wrong_passphrase_fails(self):
        enc = self.aes.encrypt(b"data", "correct")
        dec = self.aes.decrypt(enc.data, "wrong")
        assert not dec.ok

    def test_tamper_fails(self):
        enc = self.aes.encrypt(b"sensitive", "pw")
        tampered = enc.data[:-4] + "XXXX"
        assert not self.aes.decrypt(tampered, "pw").ok

    def test_aad_authentication(self):
        enc = self.aes.encrypt(b"data", "pw", aad=b"context")
        assert not self.aes.decrypt(enc.data, "pw", aad=b"wrong_context").ok
        assert self.aes.decrypt(enc.data, "pw", aad=b"context").ok

    def test_unique_ciphertexts(self):
        e1 = self.aes.encrypt(b"same", "pw")
        e2 = self.aes.encrypt(b"same", "pw")
        assert e1.data != e2.data  # different nonces/salts


# ── TOTP ─────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not _HAS_PYOTP, reason="pyotp not installed")
class TestTOTP:
    def setup_method(self):
        self.engine = TOTPEngine()

    def test_valid_code(self):
        import pyotp
        secret = self.engine.generate_secret()
        code = pyotp.TOTP(secret).now()
        assert self.engine.verify_code(secret, code, "user1").ok

    def test_invalid_code(self):
        secret = self.engine.generate_secret()
        assert not self.engine.verify_code(secret, "000000", "user2").ok

    def test_replay_protection(self):
        import pyotp
        secret = self.engine.generate_secret()
        code = pyotp.TOTP(secret).now()
        assert self.engine.verify_code(secret, code, "user3").ok
        # Same code, same user_id → replay
        assert not self.engine.verify_code(secret, code, "user3").ok

    def test_backup_codes(self):
        codes, hashes = self.engine.generate_backup_codes(count=8)
        assert len(codes) == 8
        assert self.engine.verify_backup_code(codes[0], hashes).ok
        assert not self.engine.verify_backup_code("BADCODE", hashes).ok


# ── JWT ───────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not _HAS_JWT, reason="PyJWT not installed")
class TestJWT:
    def setup_method(self):
        self.eng = JWTEngine()

    def test_issue_and_validate(self):
        tok = self.eng.issue_access_token("alice", ["admin"])
        assert tok.ok
        val = self.eng.validate_token(tok.data)
        assert val.ok
        assert val.data["sub"] == "alice"
        assert "admin" in val.data["roles"]

    def test_revocation(self):
        tok = self.eng.issue_access_token("bob", [])
        assert self.eng.validate_token(tok.data).ok
        self.eng.revoke_token(tok.data)
        assert not self.eng.validate_token(tok.data).ok


# ── Crypto Wallet ─────────────────────────────────────────────────────────────

class TestCryptoWallet:
    def setup_method(self):
        self.wallet = CryptoWalletEngine()

    def test_mnemonic_12_words(self):
        r = self.wallet.generate_mnemonic(128)
        assert r.ok and len(r.data.split()) == 12

    def test_mnemonic_24_words(self):
        r = self.wallet.generate_mnemonic(256)
        assert r.ok and len(r.data.split()) == 24

    def test_different_mnemonics(self):
        m1 = self.wallet.generate_mnemonic(128)
        m2 = self.wallet.generate_mnemonic(128)
        assert m1.data != m2.data

    def test_key_derivation(self):
        m = self.wallet.generate_mnemonic(128)
        k = self.wallet.derive_eth_key(m.data)
        assert k.ok
        assert k.data["address"].startswith("0x")
        assert len(k.data["address"]) == 42
        assert k.data["path"] == "m/44'/60'/0'/0/0"

    def test_deterministic_derivation(self):
        m = self.wallet.generate_mnemonic(128)
        k1 = self.wallet.derive_eth_key(m.data, account=0)
        k2 = self.wallet.derive_eth_key(m.data, account=0)
        assert k1.data["address"] == k2.data["address"]

    def test_different_accounts(self):
        m = self.wallet.generate_mnemonic(128)
        k0 = self.wallet.derive_eth_key(m.data, account=0)
        k1 = self.wallet.derive_eth_key(m.data, account=1)
        assert k0.data["address"] != k1.data["address"]

    def test_address_validation(self):
        m = self.wallet.generate_mnemonic(128)
        k = self.wallet.derive_eth_key(m.data)
        assert self.wallet.validate_eth_address(k.data["address"]).ok

    def test_invalid_address(self):
        assert not self.wallet.validate_eth_address("not_an_address").ok
        assert not self.wallet.validate_eth_address("0x123").ok

    @pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
    def test_mnemonic_encryption_roundtrip(self):
        m = self.wallet.generate_mnemonic(128)
        enc = self.wallet.encrypt_mnemonic(m.data, "vault_pw")
        assert enc.ok
        dec = self.wallet.decrypt_mnemonic(enc.data, "vault_pw")
        assert dec.ok and dec.data == m.data

    @pytest.mark.skipif(not _HAS_CRYPTO, reason="cryptography not installed")
    def test_mnemonic_wrong_pw_fails(self):
        m = self.wallet.generate_mnemonic(128)
        enc = self.wallet.encrypt_mnemonic(m.data, "correct")
        dec = self.wallet.decrypt_mnemonic(enc.data, "wrong")
        assert not dec.ok


# ── Shamir ────────────────────────────────────────────────────────────────────

class TestShamir:
    def setup_method(self):
        self.shamir = ShamirSecretSharing()

    def test_split_and_reconstruct_3of5(self):
        secret = secrets.token_bytes(32)
        shares = self.shamir.split_secret(secret, n=5, m=3)
        assert shares.ok and len(shares.data) == 5
        recon = self.shamir.reconstruct_secret(shares.data[:3])
        assert recon.ok and recon.data == secret

    def test_different_share_subsets(self):
        secret = secrets.token_bytes(32)
        shares = self.shamir.split_secret(secret, n=5, m=3)
        for combo in [shares.data[:3], shares.data[1:4], shares.data[2:5]]:
            r = self.shamir.reconstruct_secret(combo)
            assert r.ok and r.data == secret

    def test_2of5_wrong(self):
        secret = secrets.token_bytes(32)
        shares = self.shamir.split_secret(secret, n=5, m=3)
        r2 = self.shamir.reconstruct_secret(shares.data[:2])
        assert not (r2.ok and r2.data == secret)  # 2 shares cannot reconstruct

    def test_invalid_params(self):
        assert not self.shamir.split_secret(b"x" * 32, n=2, m=3).ok  # m > n
        assert not self.shamir.split_secret(b"x" * 32, n=5, m=1).ok  # m < 2

    def test_all_shares_reconstruct(self):
        secret = secrets.token_bytes(16)
        shares = self.shamir.split_secret(secret, n=3, m=2)
        recon = self.shamir.reconstruct_secret(shares.data)  # all 3
        assert recon.ok and recon.data == secret


# ── Threat Detection ─────────────────────────────────────────────────────────

class TestThreatDetection:
    def setup_method(self):
        self.td = ThreatDetectionEngine()

    def test_rate_limit_under(self):
        for _ in range(5):
            self.td.check_rate_limit("10.0.0.1", max_req=10, window_s=60)
        assert self.td.check_rate_limit("10.0.0.1", max_req=10, window_s=60).ok

    def test_rate_limit_exceeded(self):
        for _ in range(10):
            self.td.check_rate_limit("10.0.0.2", max_req=5, window_s=60)
        assert not self.td.check_rate_limit("10.0.0.2", max_req=5, window_s=60).ok

    def test_brute_force_lockout(self):
        for _ in range(5):
            self.td.record_failed_login("charlie", "1.1.1.1", max_attempts=5)
        locked = self.td.record_failed_login("charlie", "1.1.1.1", max_attempts=5)
        assert not locked.ok
        assert locked.metadata.get("locked_out")

    def test_clear_resets_lockout(self):
        for _ in range(5):
            self.td.record_failed_login("dave", "2.2.2.2", max_attempts=5)
        self.td.clear_failed_logins("dave")
        # Should succeed now
        result = self.td.record_failed_login("dave", "2.2.2.2", max_attempts=5)
        assert result.ok  # counter reset, 1 fail out of 5

    def test_entropy_high(self):
        assert self.td.check_entropy("correct horse battery staple", 40).ok

    def test_entropy_low(self):
        assert not self.td.check_entropy("aaa", 40).ok

    def test_threat_summary(self):
        self.td.check_rate_limit("9.9.9.9", max_req=1, window_s=60)
        self.td.check_rate_limit("9.9.9.9", max_req=1, window_s=60)  # triggers rate limit
        summary = self.td.threat_summary()
        assert summary["total"] >= 1
