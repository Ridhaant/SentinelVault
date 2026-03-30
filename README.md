<div align="center">

```
███████╗███████╗███╗  ██╗████████╗██╗███╗  ██╗███████╗██╗    
██╔════╝██╔════╝████╗ ██║╚══██╔══╝██║████╗ ██║██╔════╝██║    
███████╗█████╗  ██╔██╗██║   ██║   ██║██╔██╗██║█████╗  ██║    
╚════██║██╔══╝  ██║╚████║   ██║   ██║██║╚████║██╔══╝  ██║    
███████║███████╗██║ ╚███║   ██║   ██║██║ ╚███║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚══╝   ╚═╝   ╚═╝╚═╝  ╚══╝╚══════╝╚══════╝
          ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗              
          ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝              
          ██║   ██║███████║██║   ██║██║     ██║                 
          ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║                 
           ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║                 
            ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝                
```

# SentinelVault

**Production-Grade Cybersecurity Portfolio Platform**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Cryptography](https://img.shields.io/badge/AES--256--GCM-FIPS_Approved-76B900?style=for-the-badge)](https://cryptography.io)
[![OWASP](https://img.shields.io/badge/OWASP-Top_10_Mitigated-blue?style=for-the-badge)](https://owasp.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](./LICENSE)

<br/>

> **A comprehensive self-hosted cybersecurity toolkit demonstrating production mastery of:**
> cryptography · identity · crypto wallets · threat detection · audit trails

<br/>

[⚡ Quickstart](#quickstart) · [🏗 Architecture](#architecture) · [🔐 Features](#features) · [💎 Wallet](#wallet-security) · [🛡 Threat Detection](#threat-detection)

</div>

---

## ✦ What is SentinelVault?

SentinelVault is a **self-hostable cybersecurity platform** that demonstrates production-grade implementation of every major security domain:

```
┌────────────────────────────────────────────────────────────────────┐
│                    SentinelVault Stack                             │
│                                                                    │
│  CRYPTOGRAPHY                  IDENTITY                            │
│  AES-256-GCM (AEAD)            Argon2id password hashing           │
│  ECDSA P-256 / secp256k1       TOTP 2FA (RFC 6238)                 │
│  ECDH P-256 (ECDH)             JWT HS256/RS256                     │
│  PBKDF2 / HKDF                 RBAC + session rotation             │
│                                                                    │
│  CRYPTO WALLET                 THREAT DETECTION                    │
│  BIP-39 mnemonics              Token bucket rate limiting          │
│  BIP-32/44 HD derivation       Brute-force lockout (OWASP)         │
│  secp256k1 ECDSA signing       Entropy validation (NIST SP 800-63B)│
│  EIP-55 checksum               Port scanner + service fingerprint  │
│  MetaMask personal_sign        SSL/TLS certificate inspector       │
│  Shamir's m-of-n multi-sig     Timing attack mitigation            │
│                                                                    │
│  AUDIT TRAIL                   SECURE CHANNEL                      │
│  SHA-256 chained JSONL         ECDH P-256 key exchange             │
│  Tamper-evident log            HKDF session key derivation         │
│  Integrity verification        Forward-secret AES-256-GCM channel  │
└────────────────────────────────────────────────────────────────────┘
```

---

## ✦ Features

### 🔐 Cryptography
- **AES-256-GCM** authenticated encryption (NIST SP 800-38D) — FIPS-approved AEAD cipher
- **PBKDF2-SHA256** key derivation with 600,000 iterations (OWASP 2023)
- **ECDSA P-256** and **secp256k1** signing — covers both TLS and Ethereum ecosystems
- **ECDH P-256** ephemeral key exchange → **HKDF-SHA256** session key → forward-secret channel

### 🔑 Identity & Authentication
- **Argon2id** password hashing (PHC winner, OWASP 2023 recommended): t=3, m=64MB, p=2
- **TOTP 2FA** (RFC 6238): 160-bit secrets, ±1 window, replay protection, backup codes
- **JWT** issuance/validation (HS256) with revocation list and auto-pruning
- **Brute-force lockout**: 5 attempts → 15-minute lockout (OWASP recommendation)

### 💎 Crypto Wallet Security
- **BIP-39** mnemonic generation: 128-bit (12 words) or 256-bit (24 words) via OS CSPRNG
- **BIP-32/BIP-44** HD key derivation at `m/44'/60'/0'/0/{n}` (Ethereum standard)
- **secp256k1** ECDSA — Ethereum-native curve — compressed public key
- **EIP-55** checksum address validation — detects copy-paste corruption
- **MetaMask personal_sign** — `\x19Ethereum Signed Message:\n` prefix compatible
- **AES-256-GCM mnemonic encryption** — only safe way to persist a seed phrase
- **Shamir's Secret Sharing** (m-of-n) — split private key into n shares, need m to reconstruct

### 🚨 Threat Detection
- **Token bucket rate limiter** per IP — 60 req/min configurable
- **Brute-force detector** — tracks per-user failed logins with sliding window
- **Shannon entropy check** — flags weak passwords/keys below NIST threshold
- **Port scanner** — TCP connect scan with service fingerprinting (15 common ports)
- **SSL/TLS inspector** — expiry, weak protocol, cipher strength detection

### 📋 Tamper-Evident Audit Log
- **SHA-256 chain**: every entry stores `prev_hash` + `self_hash`
- `verify_chain()` walks entire history and detects any modification
- Event taxonomy: AUTH, CRYPTO, WALLET, ADMIN, THREAT, INTEGRITY
- Append-only JSONL — no delete or update operations

---

## ✦ Quickstart

```bash
git clone https://github.com/Ridhaant/sentinel-vault.git
cd sentinel-vault

# Install dependencies
pip install -r requirements.txt

# Run self-tests
python src/sentinel_vault.py

# Launch dashboard
python sentinel_dashboard.py
```

Open **http://localhost:8090**

---

## ✦ Usage Examples

### AES-256-GCM Encryption

```python
from src.sentinel_vault import AES256GCMVault

aes = AES256GCMVault()

# Encrypt — returns base64url bundle with salt + nonce embedded
result = aes.encrypt(b"top secret message", passphrase="my-passphrase")
assert result.ok
bundle = result.data   # "gK3bX...AeB2=="

# Decrypt — authenticated; fails if passphrase wrong or data tampered
plain = aes.decrypt(bundle, passphrase="my-passphrase")
assert plain.data == b"top secret message"
```

### Argon2id Password Hashing

```python
from src.sentinel_vault import PasswordManager

pm = PasswordManager()

# Hash (Argon2id: t=3, m=64MB, p=2)
h = pm.hash_password("correct horse battery staple")

# Verify (constant-time)
result = pm.verify_password("correct horse battery staple", h.data)
assert result.ok

# Generate a cryptographically secure password
pw = PasswordManager.generate_secure_password(length=20)
```

### TOTP 2FA

```python
from src.sentinel_vault import TOTPEngine
import pyotp

totp = TOTPEngine()
secret = totp.generate_secret()          # 160-bit base32

# Provisioning URI for QR code
uri = totp.provisioning_uri(secret, "alice@example.com")

# Verify (replay-protected, ±1 window)
code = pyotp.TOTP(secret).now()
result = totp.verify_code(secret, code, user_id="alice")
assert result.ok
```

### HD Wallet Generation

```python
from src.sentinel_vault import CryptoWalletEngine

wallet = CryptoWalletEngine()

# Generate 24-word mnemonic (256-bit entropy, OS CSPRNG)
mnemonic = wallet.generate_mnemonic(strength=256)

# Derive Ethereum key at m/44'/60'/0'/0/0
key_info = wallet.derive_eth_key(mnemonic.data, account=0)
print(key_info.data["address"])   # 0xA3f2... (EIP-55 checksum)

# Encrypt mnemonic before any storage
encrypted = wallet.encrypt_mnemonic(mnemonic.data, passphrase="vault-key")

# Validate any Ethereum address
result = wallet.validate_eth_address("0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B")
```

### Shamir's Secret Sharing (m-of-n)

```python
from src.sentinel_vault import ShamirSecretSharing
import secrets

shamir = ShamirSecretSharing()
private_key = secrets.token_bytes(32)

# Split into 5 shares, any 3 reconstruct
split = shamir.split_secret(private_key, n=5, m=3)
shares = split.data   # [(1, bytes), (2, bytes), ..., (5, bytes)]

# Give one share to each custodian (hardware wallet, lawyer, cold storage, etc.)

# Reconstruct from any 3 shares — 2 reveals ZERO information
recon = shamir.reconstruct_secret(shares[:3])
assert recon.data == private_key
```

### Tamper-Evident Audit Log

```python
from src.sentinel_vault import TamperEvidentAuditLog, AuditEventType

log = TamperEvidentAuditLog("audit/events.jsonl")
log.append(AuditEventType.AUTH, "alice", "login_success", {"ip": "192.168.1.5"})
log.append(AuditEventType.WALLET, "alice", "key_derived", {"path": "m/44'/60'/0'/0/0"})

# Verify entire chain
result = log.verify_chain()
assert result.ok   # True → chain intact; False → tampered
print(result.data)  # {'entries': 2, 'status': 'chain_intact', 'tip_hash': 'a3b2c1…'}
```

---

## ✦ Self-Test Output

```
╔══════════════════════════════════╗
║  SENTINEL VAULT  — Self-Test     ║
╚══════════════════════════════════╝

  ✓ PASS  audit_chain_integrity
  ✓ PASS  password_hash
  ✓ PASS  password_verify_correct
  ✓ PASS  password_verify_wrong
  ✓ PASS  aes_encrypt
  ✓ PASS  aes_decrypt_correct
  ✓ PASS  aes_decrypt_wrong_pw
  ✓ PASS  totp_secret_gen
  ✓ PASS  totp_verify_valid
  ✓ PASS  totp_verify_invalid
  ✓ PASS  backup_code_verify
  ✓ PASS  jwt_issue
  ✓ PASS  jwt_validate
  ✓ PASS  jwt_revoke
  ✓ PASS  wallet_mnemonic_128bit
  ✓ PASS  wallet_mnemonic_256bit
  ✓ PASS  wallet_key_derivation
  ✓ PASS  wallet_address_validate
  ✓ PASS  wallet_mnemonic_encrypt
  ✓ PASS  wallet_mnemonic_decrypt
  ✓ PASS  shamir_split
  ✓ PASS  shamir_reconstruct_3of5
  ✓ PASS  shamir_2of5_wrong
  ✓ PASS  rate_limit
  ✓ PASS  brute_force_lockout
  ✓ PASS  entropy_check_pass
  ✓ PASS  entropy_check_fail

  Results: 27/27 passed
  ✅ All tests passed — SentinelVault is operational
```

---

## ✦ Security Standards Implemented

| Standard | Implementation |
|----------|---------------|
| FIPS 140-2 | AES-256-GCM, SHA-256, ECDSA P-256, HMAC-SHA256 |
| NIST SP 800-63B | Shannon entropy validation, secure password generation |
| NIST SP 800-90A | OS CSPRNG (secrets module) for all key generation |
| OWASP Top 10 | Rate limiting, brute-force protection, input validation |
| OWASP Auth Cheat Sheet | Argon2id hashing, lockout policy, TOTP |
| RFC 6238 | TOTP with replay protection and backup codes |
| BIP-39/32/44 | HD wallet derivation, mnemonic encoding |
| EIP-55 | Ethereum address checksum encoding and validation |
| Shamir 1979 | Information-theoretic secret sharing over GF(prime) |

---

## ✦ Project Structure

```
sentinel-vault/
├── src/
│   └── sentinel_vault.py      ← Core engine (all subsystems)
├── sentinel_dashboard.py      ← Plotly Dash UI (8 tabs)
├── requirements.txt
├── audit/                     ← SHA-256 chained audit log (auto-created)
├── tests/
│   └── test_sentinel.py       ← pytest suite
└── README.md
```

---

## ✦ Author

**[Ridhaant Ajoy Thackur](https://github.com/Ridhaant)**
*Cybersecurity Engineer · Systems Engineer · LNMIIT Jaipur*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat-square&logo=linkedin&logoColor=white)](https://linkedin.com/in/ridhaant-thackur-09947a1b0)
[![GitHub](https://img.shields.io/badge/GitHub-@Ridhaant-181717?style=flat-square&logo=github&logoColor=white)](https://github.com/Ridhaant)
[![Email](https://img.shields.io/badge/Email-redantthakur%40gmail.com-D14836?style=flat-square&logo=gmail&logoColor=white)](mailto:redantthakur@gmail.com)

---

## License

MIT © 2026 Ridhaant Ajoy Thackur
