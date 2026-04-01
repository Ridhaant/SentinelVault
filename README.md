<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=24&duration=2500&pause=800&color=FF6B35&center=true&vCenter=true&width=800&lines=SentinelVault;Security-First+Codebase+%7C+Enterprise+Auth;TOTP+2FA+(RFC+6238)+%7C+RBAC+%7C+CI+Scanning;Zero+Hardcoded+Secrets+Across+30%2C595+Lines" alt="SentinelVault" />

<br/>

![Security](https://img.shields.io/badge/Focus-AppSec%20%2B%20DevSecOps-FF6B35?style=for-the-badge&logo=hackthebox&logoColor=white)
![Auth](https://img.shields.io/badge/Auth-1%2C459%20Lines-7c3aed?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

<br/>

<img src="https://skillicons.dev/icons?i=python,linux,docker,git&theme=dark" />

<br/><br/>

![TOTP 2FA](https://img.shields.io/badge/TOTP_2FA_RFC_6238-FF6B35?style=flat-square)
![RBAC](https://img.shields.io/badge/RBAC-7c3aed?style=flat-square)
![OAuth](https://img.shields.io/badge/Google_OAuth-4285F4?style=flat-square&logo=google&logoColor=white)
![Flask-Login](https://img.shields.io/badge/Flask_Login-000000?style=flat-square&logo=flask&logoColor=white)
![SHA-256](https://img.shields.io/badge/SHA--256-000000?style=flat-square)
![bcrypt](https://img.shields.io/badge/bcrypt-00599C?style=flat-square)
![OWASP](https://img.shields.io/badge/OWASP_Top_10-000000?style=flat-square)
![ZMQ](https://img.shields.io/badge/ZMQ_Hardened-DF0000?style=flat-square&logo=zeromq&logoColor=white)

*Sole-authored by **[Ridhaant Ajoy Thackur](https://github.com/Ridhaant)** · Security layer for [AlgoStack](https://github.com/Ridhaant/AlgoStack)*

</div>

---

## ⚡ What Is SentinelVault?

The security perimeter for a **30,595-line production financial platform** — featuring a **1,459-line self-hosted enterprise authentication system** (TOTP 2FA, RBAC, multi-tenant, OAuth), CI-compatible secret scanning, append-only audit logging, and ZMQ socket hardening. **Zero hardcoded secrets** enforced across the entire codebase.

---

## 📊 Security Posture

| Layer | Implementation | Status |
|:---|:---|:---:|
| **TOTP 2FA** | RFC 6238, pyotp, QR enrolment, ±1 step, 8 bcrypt backup codes | ✅ PROD |
| **RBAC** | admin / analyst / client_readonly + filesystem-level tenant isolation | ✅ PROD |
| **Secrets** | Zero hardcoded across 30,595 lines — `.env` only, SecretManager | ✅ PROD |
| **Token Reset** | 48-char hex, 30-min expiry, one-time-use, replay-resistant | ✅ PROD |
| **Audit Trail** | 20MB rotating, append-only, immutable, tamper-evident | ✅ PROD |
| **CI Scanning** | `secrets_audit.py` — regex for tokens, keys, passwords | ✅ PROD |
| **Pre-commit** | `.githooks/pre-commit` runs scanner before every commit | ✅ PROD |
| **ZMQ Hardening** | SNDHWM=2, LINGER=0, SNDTIMEO=5ms — no DoS, no hang | ✅ PROD |
| **Atomic Writes** | write-to-.tmp + os.replace — zero partial-read corruption | ✅ PROD |

---

## 🏗️ Architecture

```mermaid
graph TD
    subgraph "🔒 Enterprise Auth (1,459 lines)"
        TOTP["TOTP 2FA<br/>RFC 6238 · pyotp<br/>QR + backup codes"]
        RBAC["RBAC<br/>admin / analyst / readonly<br/>Per-org file roots"]
        AUDIT["Append-Only Audit<br/>20MB rotating<br/>No delete, no update"]
        OAUTH["Google OAuth<br/>Env-configured"]
    end
    subgraph "🛡️ CI Pipeline"
        SCAN["secrets_audit.py<br/>Regex token scanner"]
        HOOK["Pre-commit hook<br/>.githooks/pre-commit"]
        FAIL["❌ Block merge on leak"]
    end
    subgraph "🔗 IPC Hardening"
        ZMQ["ZMQ Sockets<br/>SNDHWM=2 · LINGER=0<br/>SNDTIMEO=5ms"]
        ATOMIC["Atomic File Writes<br/>os.replace — POSIX"]
    end
    HOOK --> SCAN --> FAIL
    TOTP & RBAC & AUDIT & OAUTH --> ZMQ & ATOMIC

    style TOTP fill:#0d1117,stroke:#FF6B35,stroke-width:2px,color:#FF6B35
    style SCAN fill:#0d1117,stroke:#f85149,stroke-width:2px,color:#f85149
```

---

## 🔗 Proven in Production

Secures [AlgoStack](https://github.com/Ridhaant/AlgoStack) — a 30,595-line, 16-process live trading platform. Every auth event, every price write, every IPC message passes through SentinelVault's security controls.

---

## 📦 Related

[![AlgoStack](https://img.shields.io/badge/AlgoStack-Parent%20Platform-00D4FF?style=for-the-badge)](https://github.com/Ridhaant/AlgoStack)
[![nexus-price-bus](https://img.shields.io/badge/nexus--price--bus-ZMQ%20Hardened-DF0000?style=for-the-badge)](https://github.com/Ridhaant/Nexus-Price-Bus)
[![sentitrade](https://img.shields.io/badge/sentitrade-SHA--256%20Dedup-3fb950?style=for-the-badge)](https://github.com/Ridhaant/SentiTrade)
[![vectorsweep](https://img.shields.io/badge/vectorsweep-Secret--Free%20GPU-76B900?style=for-the-badge)](https://github.com/Ridhaant/VectorSweep)

---

<div align="center">

© 2026 Ridhaant Ajoy Thackur · MIT License

</div>
