"""
sentinel_dashboard.py — SentinelVault Interactive Security Dashboard
=====================================================================
Plotly Dash UI exposing all SentinelVault subsystems:

  /          — System status + threat summary
  /crypto    — AES-256-GCM encrypt/decrypt demo
  /wallet    — HD wallet generation + MetaMask connect
  /auth      — Password hashing + TOTP + JWT demo
  /audit     — Tamper-evident audit log viewer + chain verifier
  /threats   — Real-time threat feed + rate-limit stats
  /scanner   — Port scanner + SSL inspector
  /shamir    — Shamir's Secret Sharing m-of-n demo

Author: Ridhaant Ajoy Thackur  |  github.com/Ridhaant
"""

from __future__ import annotations

import json
import logging
import os
import sys

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import dash
from dash import dcc, html, Input, Output, State, callback, no_update
import dash_bootstrap_components as dbc
import plotly.graph_objects as go

from sentinel_vault import (
    SentinelVault, AES256GCMVault, PasswordManager, TOTPEngine,
    JWTEngine, CryptoWalletEngine, ShamirSecretSharing,
    ThreatDetectionEngine, TamperEvidentAuditLog, AuditEventType,
    _HAS_CRYPTO, _HAS_ARGON2, _HAS_PYOTP, _HAS_JWT,
)

log = logging.getLogger("sentinel_dashboard")

# ── Colours ───────────────────────────────────────────────────────────────────
BG     = "#0a0e1a"
CARD   = "#111827"
BORDER = "#1e293b"
ACCENT = "#3b82f6"
GREEN  = "#10b981"
RED    = "#ef4444"
AMBER  = "#f59e0b"
DIM    = "#6b7280"
WHITE  = "#f1f5f9"

CARD_STYLE = {
    "background": CARD, "border": f"1px solid {BORDER}",
    "borderRadius": "8px", "padding": "20px", "marginBottom": "16px",
}

# ── Vault instance ────────────────────────────────────────────────────────────
vault = SentinelVault(log_path="audit/sentinel_audit.jsonl")

# ── App ───────────────────────────────────────────────────────────────────────
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.CYBORG],
    suppress_callback_exceptions=True,
    title="SentinelVault",
)

# ── Nav ───────────────────────────────────────────────────────────────────────
NAV = html.Div(
    style={"background": "#0d1117", "borderBottom": f"1px solid {BORDER}",
           "padding": "12px 24px", "display": "flex", "alignItems": "center",
           "justifyContent": "space-between"},
    children=[
        html.Div([
            html.Span("🛡️ ", style={"fontSize": "20px"}),
            html.Span("SENTINEL", style={"color": ACCENT, "fontWeight": "bold",
                                          "fontSize": "18px", "letterSpacing": "2px"}),
            html.Span("VAULT", style={"color": WHITE, "fontWeight": "bold",
                                       "fontSize": "18px", "letterSpacing": "2px"}),
        ]),
        html.Div(
            style={"display": "flex", "gap": "8px"},
            children=[
                dcc.Link(b, href=h, style={"color": DIM, "textDecoration": "none",
                                            "padding": "6px 14px", "borderRadius": "6px",
                                            "fontSize": "13px", "border": f"1px solid {BORDER}"})
                for b, h in [
                    ("Overview", "/"), ("Crypto", "/crypto"), ("Wallet", "/wallet"),
                    ("Auth", "/auth"), ("Audit", "/audit"), ("Threats", "/threats"),
                    ("Scanner", "/scanner"), ("Shamir", "/shamir"),
                ]
            ],
        ),
        html.Div([
            html.A("GitHub", href="https://github.com/Ridhaant", target="_blank",
                   style={"color": ACCENT, "fontSize": "13px", "marginRight": "12px"}),
            html.A("LinkedIn", href="https://linkedin.com/in/ridhaant-thackur-09947a1b0",
                   target="_blank", style={"color": ACCENT, "fontSize": "13px"}),
        ]),
    ],
)

app.layout = html.Div(
    style={"background": BG, "minHeight": "100vh", "color": WHITE,
           "fontFamily": "'Inter', 'Segoe UI', sans-serif"},
    children=[
        NAV,
        dcc.Location(id="url", refresh=False),
        html.Div(id="page-content", style={"padding": "24px", "maxWidth": "1200px",
                                             "margin": "0 auto"}),
    ],
)


# ════════════════════════════════════════════════════════════════════════════
# PAGES
# ════════════════════════════════════════════════════════════════════════════

def page_overview():
    status = vault.system_status()
    checks = [
        ("cryptography (AES-GCM/RSA/ECDSA)", status["cryptography"]),
        ("argon2-cffi (Argon2id hashing)",    status["argon2"]),
        ("pyotp (TOTP 2FA RFC 6238)",          status["pyotp"]),
        ("PyJWT (JWT HS256/RS256)",            status["pyjwt"]),
        ("Audit chain integrity",              status["audit_ok"]),
    ]
    capability_rows = []
    for label, ok in checks:
        capability_rows.append(
            html.Div(style={"display": "flex", "alignItems": "center",
                             "padding": "8px 0", "borderBottom": f"1px solid {BORDER}"},
                     children=[
                         html.Span("✓" if ok else "✗",
                                   style={"color": GREEN if ok else AMBER,
                                          "fontWeight": "bold", "marginRight": "12px",
                                          "width": "20px"}),
                         html.Span(label, style={"color": WHITE if ok else DIM}),
                     ]),
        )
    threat_sum = vault.threat.threat_summary()
    return html.Div([
        html.H2("🛡️ SentinelVault — Security Posture Dashboard",
                style={"color": WHITE, "marginBottom": "24px"}),
        html.P("Production-grade cybersecurity toolkit: cryptography, identity, wallet security, and threat detection.",
               style={"color": DIM, "marginBottom": "24px"}),
        dbc.Row([
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Subsystem Status", style={"color": ACCENT}),
                    *capability_rows,
                ]),
            ], width=6),
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Threat Summary", style={"color": RED}),
                    html.P(f"Total threats detected: {threat_sum.get('total', 0)}",
                           style={"color": WHITE}),
                    *[html.P(f"{k}: {v}", style={"color": DIM, "fontSize": "13px"})
                      for k, v in threat_sum.get("by_type", {}).items()],
                ]),
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Security Standards", style={"color": GREEN}),
                    *[html.P(s, style={"color": DIM, "fontSize": "12px"}) for s in [
                        "✓ OWASP Top 10 mitigations",
                        "✓ NIST SP 800-63B credential guidelines",
                        "✓ RFC 6238 TOTP standard",
                        "✓ BIP-39/44 wallet derivation",
                        "✓ EIP-55 address checksum",
                        "✓ FIPS-approved algorithms (AES-256, SHA-256, ECDSA P-256)",
                    ]],
                ]),
            ], width=6),
        ]),
        html.Div(style=CARD_STYLE, children=[
            html.H5("Architecture", style={"color": ACCENT}),
            html.Pre("""
  ┌────────────────────────────────────────────────────────────────────┐
  │                     SentinelVault Stack                            │
  │                                                                    │
  │  AES-256-GCM    RSA-4096    ECDSA P-256    secp256k1 (wallet)      │
  │  Argon2id       PBKDF2      TOTP RFC6238   JWT HS256/RS256          │
  │  BIP-39/32/44   EIP-55      Shamir SSS     ECDH P-256               │
  │                                                                    │
  │  TamperEvidentAuditLog ← SHA-256 chain (every entry links prev)   │
  │  ThreatDetectionEngine ← rate-limit + brute-force + entropy        │
  │  SentinelVault ← unified API exposing all subsystems               │
  └────────────────────────────────────────────────────────────────────┘
            """, style={"color": DIM, "fontSize": "12px", "background": BG,
                         "padding": "12px", "borderRadius": "6px"}),
        ]),
    ])


def page_crypto():
    return html.Div([
        html.H2("🔐 AES-256-GCM Encryption", style={"color": WHITE, "marginBottom": "8px"}),
        html.P("Authenticated encryption with PBKDF2-SHA256 key derivation (600,000 iterations).",
               style={"color": DIM, "marginBottom": "24px"}),
        dbc.Row([
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Encrypt", style={"color": ACCENT}),
                    dcc.Textarea(id="enc-plaintext", placeholder="Enter plaintext to encrypt…",
                                 style={"width": "100%", "height": "100px", "background": BG,
                                        "color": WHITE, "border": f"1px solid {BORDER}",
                                        "borderRadius": "6px", "padding": "8px"}),
                    dcc.Input(id="enc-password", type="password",
                              placeholder="Passphrase (min 12 chars recommended)",
                              style={"width": "100%", "marginTop": "8px", "background": BG,
                                     "color": WHITE, "border": f"1px solid {BORDER}",
                                     "borderRadius": "6px", "padding": "8px"}),
                    html.Button("🔒 Encrypt", id="enc-btn",
                                style={"marginTop": "10px", "background": ACCENT,
                                       "color": WHITE, "border": "none",
                                       "padding": "8px 20px", "borderRadius": "6px",
                                       "cursor": "pointer"}),
                    html.Div(id="enc-output", style={"marginTop": "12px", "wordBreak": "break-all",
                                                      "fontSize": "11px", "color": GREEN}),
                ]),
            ], width=6),
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Decrypt", style={"color": GREEN}),
                    dcc.Textarea(id="dec-bundle", placeholder="Paste encrypted bundle here…",
                                 style={"width": "100%", "height": "100px", "background": BG,
                                        "color": WHITE, "border": f"1px solid {BORDER}",
                                        "borderRadius": "6px", "padding": "8px"}),
                    dcc.Input(id="dec-password", type="password", placeholder="Passphrase",
                              style={"width": "100%", "marginTop": "8px", "background": BG,
                                     "color": WHITE, "border": f"1px solid {BORDER}",
                                     "borderRadius": "6px", "padding": "8px"}),
                    html.Button("🔓 Decrypt", id="dec-btn",
                                style={"marginTop": "10px", "background": GREEN,
                                       "color": WHITE, "border": "none",
                                       "padding": "8px 20px", "borderRadius": "6px",
                                       "cursor": "pointer"}),
                    html.Div(id="dec-output", style={"marginTop": "12px", "color": WHITE}),
                ]),
            ], width=6),
        ]),
    ])


def page_wallet():
    return html.Div([
        html.H2("💎 Crypto Wallet", style={"color": WHITE, "marginBottom": "8px"}),
        html.P("BIP-39 mnemonic generation · BIP-44 HD key derivation · EIP-55 address · MetaMask sign · Shamir backup",
               style={"color": DIM, "marginBottom": "24px"}),
        html.Div(style=CARD_STYLE, children=[
            html.H5("⚠️ Security Notice", style={"color": AMBER}),
            html.P("Private keys generated here are for demonstration. In production, keys NEVER leave the client device. Use hardware wallets (Ledger/Trezor) for real funds.",
                   style={"color": DIM, "fontSize": "13px"}),
        ]),
        dbc.Row([
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Generate HD Wallet", style={"color": ACCENT}),
                    html.Div(style={"display": "flex", "gap": "8px", "marginBottom": "12px"},
                             children=[
                                 html.Button("128-bit (12 words)", id="gen-128-btn",
                                             style={"background": ACCENT, "color": WHITE,
                                                    "border": "none", "padding": "8px 16px",
                                                    "borderRadius": "6px", "cursor": "pointer"}),
                                 html.Button("256-bit (24 words)", id="gen-256-btn",
                                             style={"background": "#7c3aed", "color": WHITE,
                                                    "border": "none", "padding": "8px 16px",
                                                    "borderRadius": "6px", "cursor": "pointer"}),
                             ]),
                    html.Div(id="wallet-output", style={"marginTop": "12px"}),
                ]),
            ], width=7),
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Validate Address", style={"color": GREEN}),
                    dcc.Input(id="addr-input",
                              placeholder="0x… Ethereum address",
                              style={"width": "100%", "background": BG, "color": WHITE,
                                     "border": f"1px solid {BORDER}", "borderRadius": "6px",
                                     "padding": "8px"}),
                    html.Button("Validate EIP-55", id="addr-btn",
                                style={"marginTop": "10px", "background": GREEN,
                                       "color": WHITE, "border": "none",
                                       "padding": "8px 16px", "borderRadius": "6px",
                                       "cursor": "pointer"}),
                    html.Div(id="addr-output", style={"marginTop": "12px"}),
                ]),
                html.Div(style=CARD_STYLE, children=[
                    html.H5("MetaMask Connect", style={"color": AMBER}),
                    html.P("Connect your MetaMask wallet to sign a challenge message, proving address ownership.",
                           style={"color": DIM, "fontSize": "13px"}),
                    html.Div(id="metamask-status",
                             children=html.P("JavaScript required for MetaMask integration",
                                             style={"color": DIM, "fontSize": "12px"})),
                ]),
            ], width=5),
        ]),
    ])


def page_auth():
    return html.Div([
        html.H2("🔑 Authentication", style={"color": WHITE, "marginBottom": "8px"}),
        html.P("Argon2id password hashing · TOTP 2FA · JWT token issuance",
               style={"color": DIM, "marginBottom": "24px"}),
        dbc.Row([
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Password Security", style={"color": ACCENT}),
                    html.P("Argon2id: t=3, m=65536 (64MB RAM), p=2 — OWASP 2023 recommended",
                           style={"color": DIM, "fontSize": "12px"}),
                    dcc.Input(id="pw-input", type="password",
                              placeholder="Enter password to hash",
                              style={"width": "100%", "background": BG, "color": WHITE,
                                     "border": f"1px solid {BORDER}", "borderRadius": "6px",
                                     "padding": "8px"}),
                    html.Button("Hash (Argon2id)", id="pw-hash-btn",
                                style={"marginTop": "10px", "background": ACCENT,
                                       "color": WHITE, "border": "none",
                                       "padding": "8px 16px", "borderRadius": "6px",
                                       "cursor": "pointer"}),
                    html.Div(id="pw-hash-output", style={"marginTop": "12px",
                                                          "fontSize": "11px",
                                                          "wordBreak": "break-all"}),
                    html.Hr(style={"borderColor": BORDER}),
                    html.Button("Generate Secure Password", id="pw-gen-btn",
                                style={"background": "#059669", "color": WHITE,
                                       "border": "none", "padding": "8px 16px",
                                       "borderRadius": "6px", "cursor": "pointer"}),
                    html.Div(id="pw-gen-output", style={"marginTop": "10px",
                                                         "color": GREEN, "fontFamily": "monospace"}),
                ]),
            ], width=6),
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("TOTP 2FA Generator", style={"color": AMBER}),
                    html.P("RFC 6238 · Compatible with Google Authenticator · Replay-protected",
                           style={"color": DIM, "fontSize": "12px"}),
                    html.Button("Generate TOTP Secret", id="totp-gen-btn",
                                style={"background": AMBER, "color": "#1a1a1a",
                                       "border": "none", "padding": "8px 16px",
                                       "borderRadius": "6px", "cursor": "pointer"}),
                    html.Div(id="totp-output", style={"marginTop": "12px"}),
                ]),
                html.Div(style=CARD_STYLE, children=[
                    html.H5("JWT Token Demo", style={"color": "#a78bfa"}),
                    dcc.Input(id="jwt-user", placeholder="user_id",
                              style={"width": "100%", "background": BG, "color": WHITE,
                                     "border": f"1px solid {BORDER}", "borderRadius": "6px",
                                     "padding": "8px", "marginBottom": "8px"}),
                    html.Button("Issue JWT", id="jwt-issue-btn",
                                style={"background": "#7c3aed", "color": WHITE,
                                       "border": "none", "padding": "8px 16px",
                                       "borderRadius": "6px", "cursor": "pointer"}),
                    html.Div(id="jwt-output", style={"marginTop": "12px", "fontSize": "11px",
                                                      "wordBreak": "break-all"}),
                ]),
            ], width=6),
        ]),
    ])


def page_audit():
    result = vault.audit.verify_chain()
    chain_ok = result.ok
    data = result.data or {}
    return html.Div([
        html.H2("📋 Tamper-Evident Audit Log", style={"color": WHITE, "marginBottom": "8px"}),
        html.P("SHA-256 chained JSONL log — every entry hashes the previous. Any modification breaks the chain.",
               style={"color": DIM, "marginBottom": "24px"}),
        html.Div(style=CARD_STYLE, children=[
            html.H5("Chain Integrity", style={"color": GREEN if chain_ok else RED}),
            html.P(f"Status: {'✓ INTACT' if chain_ok else '✗ TAMPERED'}",
                   style={"color": GREEN if chain_ok else RED, "fontWeight": "bold"}),
            html.P(f"Entries verified: {data.get('entries', 0)}",
                   style={"color": DIM}),
            html.P(f"Tip hash: {data.get('tip_hash', '—')}",
                   style={"color": DIM, "fontFamily": "monospace", "fontSize": "12px"}),
        ]),
        html.Div(style=CARD_STYLE, children=[
            html.H5("Add Test Entry", style={"color": ACCENT}),
            dcc.Input(id="audit-action", placeholder="Action to log (e.g. test_login)",
                      style={"width": "60%", "background": BG, "color": WHITE,
                             "border": f"1px solid {BORDER}", "borderRadius": "6px",
                             "padding": "8px"}),
            html.Button("Append to Log", id="audit-append-btn",
                        style={"marginLeft": "10px", "background": ACCENT,
                               "color": WHITE, "border": "none",
                               "padding": "8px 16px", "borderRadius": "6px",
                               "cursor": "pointer"}),
            html.Div(id="audit-output", style={"marginTop": "12px", "color": GREEN,
                                                "fontFamily": "monospace", "fontSize": "12px"}),
        ]),
    ])


def page_threats():
    threats = vault.threat.get_threats(last_n=50)
    summary = vault.threat.threat_summary()
    rows = []
    for t in reversed(threats[-20:]):
        color = RED if t.severity == "CRITICAL" else (AMBER if t.severity == "HIGH" else DIM)
        rows.append(html.Tr([
            html.Td(t.timestamp[:19], style={"fontSize": "11px", "color": DIM, "padding": "4px 8px"}),
            html.Td(t.threat_type, style={"color": color, "fontSize": "12px", "padding": "4px 8px"}),
            html.Td(t.severity, style={"color": color, "fontSize": "12px", "padding": "4px 8px"}),
            html.Td(t.source_ip, style={"fontSize": "11px", "color": DIM, "padding": "4px 8px"}),
            html.Td("BLOCKED" if t.blocked else "ALLOWED",
                    style={"color": RED if t.blocked else GREEN, "fontSize": "11px",
                           "padding": "4px 8px"}),
        ]))
    return html.Div([
        html.H2("🚨 Threat Detection Feed", style={"color": WHITE, "marginBottom": "8px"}),
        html.P("Real-time: rate limiting · brute-force detection · entropy checking · anomaly flagging",
               style={"color": DIM, "marginBottom": "24px"}),
        dbc.Row([
            dbc.Col([html.Div(style=CARD_STYLE, children=[
                html.H5("Threat Summary", style={"color": RED}),
                html.P(f"Total: {summary.get('total', 0)}", style={"color": WHITE}),
                *[html.P(f"{k}: {v}", style={"color": DIM, "fontSize": "13px"})
                  for k, v in summary.get("by_severity", {}).items()],
            ])], width=3),
            dbc.Col([html.Div(style=CARD_STYLE, children=[
                html.H5("Recent Threats", style={"color": AMBER}),
                html.Table(
                    children=[
                        html.Thead(html.Tr([
                            html.Th("Timestamp", style={"color": DIM, "fontSize": "11px"}),
                            html.Th("Type", style={"color": DIM, "fontSize": "11px"}),
                            html.Th("Severity", style={"color": DIM, "fontSize": "11px"}),
                            html.Th("IP", style={"color": DIM, "fontSize": "11px"}),
                            html.Th("Action", style={"color": DIM, "fontSize": "11px"}),
                        ])),
                        html.Tbody(rows or [html.Tr([
                            html.Td("No threats detected", colSpan=5,
                                    style={"color": DIM, "textAlign": "center",
                                           "padding": "12px"})
                        ])]),
                    ],
                    style={"width": "100%", "borderCollapse": "collapse"},
                ),
            ])], width=9),
        ]),
    ])


def page_scanner():
    return html.Div([
        html.H2("🔍 Security Scanner", style={"color": WHITE, "marginBottom": "8px"}),
        html.P("Port scanner · SSL/TLS certificate inspector · Service fingerprinting",
               style={"color": DIM, "marginBottom": "24px"}),
        dbc.Row([
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("Port Scanner", style={"color": ACCENT}),
                    dcc.Input(id="scan-host", placeholder="localhost or 127.0.0.1",
                              value="127.0.0.1",
                              style={"width": "100%", "background": BG, "color": WHITE,
                                     "border": f"1px solid {BORDER}", "borderRadius": "6px",
                                     "padding": "8px"}),
                    html.Button("Scan Ports", id="scan-btn",
                                style={"marginTop": "10px", "background": ACCENT,
                                       "color": WHITE, "border": "none",
                                       "padding": "8px 16px", "borderRadius": "6px",
                                       "cursor": "pointer"}),
                    html.Div(id="scan-output", style={"marginTop": "12px"}),
                ]),
            ], width=6),
            dbc.Col([
                html.Div(style=CARD_STYLE, children=[
                    html.H5("SSL/TLS Inspector", style={"color": GREEN}),
                    dcc.Input(id="ssl-host", placeholder="github.com",
                              value="github.com",
                              style={"width": "100%", "background": BG, "color": WHITE,
                                     "border": f"1px solid {BORDER}", "borderRadius": "6px",
                                     "padding": "8px"}),
                    html.Button("Inspect SSL", id="ssl-btn",
                                style={"marginTop": "10px", "background": GREEN,
                                       "color": WHITE, "border": "none",
                                       "padding": "8px 16px", "borderRadius": "6px",
                                       "cursor": "pointer"}),
                    html.Div(id="ssl-output", style={"marginTop": "12px"}),
                ]),
            ], width=6),
        ]),
    ])


def page_shamir():
    return html.Div([
        html.H2("🔑 Shamir's Secret Sharing", style={"color": WHITE, "marginBottom": "8px"}),
        html.P("Split a 32-byte private key into n shares. Any m shares reconstruct it. Mathematically proven: m-1 shares reveal ZERO information.",
               style={"color": DIM, "marginBottom": "24px"}),
        html.Div(style=CARD_STYLE, children=[
            html.H5("Split Secret", style={"color": ACCENT}),
            html.Div(style={"display": "flex", "gap": "12px", "marginBottom": "12px",
                             "alignItems": "center"},
                     children=[
                         html.Label("n (total shares):", style={"color": DIM, "width": "140px"}),
                         dcc.Input(id="shamir-n", type="number", value=5, min=2, max=20,
                                   style={"width": "80px", "background": BG, "color": WHITE,
                                          "border": f"1px solid {BORDER}", "borderRadius": "6px",
                                          "padding": "6px"}),
                         html.Label("m (threshold):", style={"color": DIM, "width": "120px"}),
                         dcc.Input(id="shamir-m", type="number", value=3, min=2, max=20,
                                   style={"width": "80px", "background": BG, "color": WHITE,
                                          "border": f"1px solid {BORDER}", "borderRadius": "6px",
                                          "padding": "6px"}),
                     ]),
            html.Button("Split New Secret", id="shamir-split-btn",
                        style={"background": ACCENT, "color": WHITE,
                               "border": "none", "padding": "8px 20px",
                               "borderRadius": "6px", "cursor": "pointer"}),
            html.Div(id="shamir-output", style={"marginTop": "16px"}),
        ]),
    ])


# ── Routing ───────────────────────────────────────────────────────────────────
@app.callback(Output("page-content", "children"), Input("url", "pathname"))
def render_page(pathname):
    p = (pathname or "/").rstrip("/") or "/"
    pages = {
        "/":        page_overview,
        "/crypto":  page_crypto,
        "/wallet":  page_wallet,
        "/auth":    page_auth,
        "/audit":   page_audit,
        "/threats": page_threats,
        "/scanner": page_scanner,
        "/shamir":  page_shamir,
    }
    return pages.get(p, page_overview)()


# ── Callbacks ─────────────────────────────────────────────────────────────────

@app.callback(Output("enc-output", "children"),
              Input("enc-btn", "n_clicks"),
              State("enc-plaintext", "value"),
              State("enc-password", "value"),
              prevent_initial_call=True)
def do_encrypt(_, plaintext, password):
    if not plaintext or not password:
        return html.P("Enter both plaintext and passphrase.", style={"color": AMBER})
    if not _HAS_CRYPTO:
        return html.P("cryptography package not installed.", style={"color": RED})
    aes = AES256GCMVault()
    result = aes.encrypt(plaintext.encode("utf-8"), password)
    if result.ok:
        vault.audit.append(AuditEventType.CRYPTO, "dashboard_user", "aes_encrypt",
                           {"algo": "AES-256-GCM", "plaintext_len": len(plaintext)})
        return [
            html.P("✓ Encrypted (copy this bundle):", style={"color": GREEN}),
            html.Code(result.data, style={"wordBreak": "break-all", "fontSize": "11px",
                                           "color": GREEN}),
        ]
    return html.P(f"Error: {result.error}", style={"color": RED})


@app.callback(Output("dec-output", "children"),
              Input("dec-btn", "n_clicks"),
              State("dec-bundle", "value"),
              State("dec-password", "value"),
              prevent_initial_call=True)
def do_decrypt(_, bundle, password):
    if not bundle or not password:
        return html.P("Enter both bundle and passphrase.", style={"color": AMBER})
    if not _HAS_CRYPTO:
        return html.P("cryptography package not installed.", style={"color": RED})
    aes = AES256GCMVault()
    result = aes.decrypt(bundle.strip(), password)
    if result.ok:
        return html.P(f"✓ Decrypted: {result.data.decode('utf-8', errors='replace')}",
                      style={"color": GREEN})
    return html.P(f"✗ {result.error}", style={"color": RED})


@app.callback(Output("wallet-output", "children"),
              [Input("gen-128-btn", "n_clicks"), Input("gen-256-btn", "n_clicks")],
              prevent_initial_call=True)
def gen_wallet(n128, n256):
    ctx = dash.callback_context
    if not ctx.triggered:
        return no_update
    strength = 256 if "256" in ctx.triggered[0]["prop_id"] else 128
    wallet_eng = CryptoWalletEngine()
    m = wallet_eng.generate_mnemonic(strength=strength)
    if not m.ok:
        return html.P(m.error, style={"color": RED})
    k = wallet_eng.derive_eth_key(m.data)
    vault.audit.append(AuditEventType.WALLET, "dashboard_user", "wallet_generated",
                       {"strength": strength, "address": k.data.get("address", "?") if k.ok else "err"})
    rows = [
        ("Mnemonic", m.data, AMBER),
        ("Address", k.data.get("address", "?") if k.ok else "—", GREEN),
        ("Path", k.data.get("path", "?") if k.ok else "—", DIM),
        ("Private Key", "⚠️ Hidden — never share or store unencrypted", RED),
    ]
    items = []
    for label, val, color in rows:
        items.append(html.Div([
            html.Span(f"{label}: ", style={"color": DIM, "fontWeight": "bold", "fontSize": "12px"}),
            html.Span(val, style={"color": color, "fontFamily": "monospace", "fontSize": "12px",
                                   "wordBreak": "break-all"}),
        ], style={"padding": "4px 0", "borderBottom": f"1px solid {BORDER}"}))
    return items


@app.callback(Output("addr-output", "children"),
              Input("addr-btn", "n_clicks"),
              State("addr-input", "value"),
              prevent_initial_call=True)
def validate_address(_, addr):
    if not addr:
        return html.P("Enter an address.", style={"color": AMBER})
    wallet_eng = CryptoWalletEngine()
    result = wallet_eng.validate_eth_address(addr)
    if result.ok:
        return html.P(f"✓ Valid — {result.metadata.get('checksum', '')}",
                      style={"color": GREEN})
    return html.P(f"✗ {result.error}", style={"color": RED})


@app.callback(Output("pw-hash-output", "children"),
              Input("pw-hash-btn", "n_clicks"),
              State("pw-input", "value"),
              prevent_initial_call=True)
def hash_password(_, pw):
    if not pw:
        return html.P("Enter a password.", style={"color": AMBER})
    pm = PasswordManager()
    result = pm.hash_password(pw)
    if result.ok:
        return [
            html.P("✓ Hash (Argon2id):", style={"color": GREEN}),
            html.Code(result.data, style={"color": DIM, "wordBreak": "break-all",
                                           "fontSize": "11px"}),
            html.P(f"Algorithm: {result.metadata.get('algorithm', '?')}",
                   style={"color": DIM, "fontSize": "12px", "marginTop": "8px"}),
        ]
    return html.P(f"Error: {result.error}", style={"color": RED})


@app.callback(Output("pw-gen-output", "children"),
              Input("pw-gen-btn", "n_clicks"),
              prevent_initial_call=True)
def gen_password(_):
    pw = PasswordManager.generate_secure_password(20)
    return html.Span(pw, style={"color": GREEN, "fontFamily": "monospace"})


@app.callback(Output("totp-output", "children"),
              Input("totp-gen-btn", "n_clicks"),
              prevent_initial_call=True)
def gen_totp(_):
    if not _HAS_PYOTP:
        return html.P("pyotp not installed.", style={"color": RED})
    totp_eng = TOTPEngine()
    secret = totp_eng.generate_secret()
    uri = totp_eng.provisioning_uri(secret, "demo@sentinelvault.io")
    backup_codes, _ = totp_eng.generate_backup_codes(count=4)
    return [
        html.P(f"Secret: {secret}", style={"color": AMBER, "fontFamily": "monospace",
                                             "fontSize": "12px"}),
        html.P("Scan in Google Authenticator:", style={"color": DIM, "marginTop": "8px"}),
        html.Code(uri[:80] + "…", style={"color": DIM, "fontSize": "10px",
                                          "wordBreak": "break-all"}),
        html.P("Backup codes (SHA-256 hashed for storage):",
               style={"color": DIM, "marginTop": "8px", "fontSize": "12px"}),
        *[html.Code(c + " ", style={"color": GREEN, "fontSize": "12px"})
          for c in backup_codes],
    ]


@app.callback(Output("jwt-output", "children"),
              Input("jwt-issue-btn", "n_clicks"),
              State("jwt-user", "value"),
              prevent_initial_call=True)
def issue_jwt(_, user_id):
    if not _HAS_JWT:
        return html.P("PyJWT not installed.", style={"color": RED})
    if not user_id:
        return html.P("Enter a user_id.", style={"color": AMBER})
    jwt_eng = JWTEngine()
    result = jwt_eng.issue_access_token(user_id, ["analyst"], {"source": "demo"})
    if result.ok:
        val = jwt_eng.validate_token(result.data)
        return [
            html.P("✓ JWT issued (HS256, 15-min TTL):", style={"color": GREEN}),
            html.Code(result.data[:80] + "…", style={"color": DIM, "fontSize": "10px",
                                                       "wordBreak": "break-all"}),
            html.P(f"Claims: {json.dumps(val.data, default=str)[:200]}" if val.ok else "",
                   style={"color": DIM, "fontSize": "11px", "marginTop": "8px"}),
        ]
    return html.P(f"Error: {result.error}", style={"color": RED})


@app.callback(Output("audit-output", "children"),
              Input("audit-append-btn", "n_clicks"),
              State("audit-action", "value"),
              prevent_initial_call=True)
def append_audit(_, action):
    if not action:
        return html.P("Enter an action.", style={"color": AMBER})
    h = vault.audit.append(AuditEventType.AUTH, "dashboard_user", action,
                            {"source": "dashboard_demo"})
    chain = vault.audit.verify_chain()
    return [
        html.P(f"✓ Appended. Self-hash: {h[:24]}…", style={"color": GREEN}),
        html.P(f"Chain status: {'✓ INTACT' if chain.ok else '✗ BROKEN'}",
               style={"color": GREEN if chain.ok else RED}),
    ]


@app.callback(Output("scan-output", "children"),
              Input("scan-btn", "n_clicks"),
              State("scan-host", "value"),
              prevent_initial_call=True)
def do_scan(_, host):
    if not host:
        return html.P("Enter a host.", style={"color": AMBER})
    result = vault.threat.scan_ports(host)
    if result.ok:
        if not result.data:
            return html.P("No open ports found.", style={"color": DIM})
        return html.Table([
            html.Tr([
                html.Td(str(p["port"]), style={"color": WHITE, "padding": "4px 8px",
                                                "fontFamily": "monospace"}),
                html.Td(p["service"], style={"color": AMBER, "padding": "4px 8px"}),
                html.Td(p["risk"], style={"color": RED if p["risk"] == "HIGH" else GREEN,
                                           "padding": "4px 8px"}),
            ])
            for p in result.data
        ], style={"borderCollapse": "collapse"})
    return html.P(f"Error: {result.error}", style={"color": RED})


@app.callback(Output("ssl-output", "children"),
              Input("ssl-btn", "n_clicks"),
              State("ssl-host", "value"),
              prevent_initial_call=True)
def inspect_ssl(_, host):
    if not host:
        return html.P("Enter a hostname.", style={"color": AMBER})
    result = vault.threat.inspect_ssl(host)
    d = result.data or {}
    color = GREEN if result.ok else (AMBER if d.get("days_to_expiry", 0) > 0 else RED)
    items = [
        html.P(f"Protocol: {d.get('protocol', '?')}", style={"color": WHITE, "fontSize": "13px"}),
        html.P(f"Cipher: {d.get('cipher', '?')} ({d.get('bits', '?')} bits)",
               style={"color": WHITE, "fontSize": "13px"}),
        html.P(f"Expires in: {d.get('days_to_expiry', '?')} days",
               style={"color": GREEN if d.get("days_to_expiry", 0) > 30 else RED,
                      "fontSize": "13px"}),
    ]
    if d.get("issues"):
        items.append(html.P(f"Issues: {', '.join(d['issues'])}", style={"color": RED}))
    return items


@app.callback(Output("shamir-output", "children"),
              Input("shamir-split-btn", "n_clicks"),
              State("shamir-n", "value"),
              State("shamir-m", "value"),
              prevent_initial_call=True)
def do_shamir(_, n, m):
    import secrets as _s
    n, m = int(n or 5), int(m or 3)
    if m > n:
        return html.P("m cannot exceed n.", style={"color": RED})
    shamir = ShamirSecretSharing()
    secret = _s.token_bytes(32)
    result = shamir.split_secret(secret, n=n, m=m)
    if not result.ok:
        return html.P(result.error, style={"color": RED})
    # Reconstruct to verify
    subset = result.data[:m]
    recon  = shamir.reconstruct_secret(subset)
    ok     = recon.ok and recon.data == secret
    shares_html = []
    for idx, share_bytes in result.data:
        shares_html.append(
            html.Div([
                html.Span(f"Share {idx}: ", style={"color": DIM, "fontWeight": "bold"}),
                html.Code(share_bytes.hex()[:32] + "…",
                          style={"color": ACCENT, "fontSize": "11px"}),
            ], style={"marginBottom": "4px"})
        )
    return [
        html.P(f"Secret (32 bytes): {secret.hex()[:32]}…",
               style={"color": AMBER, "fontFamily": "monospace", "fontSize": "12px"}),
        html.P(f"Split into {n} shares, threshold {m}:", style={"color": DIM}),
        *shares_html,
        html.Hr(style={"borderColor": BORDER}),
        html.P(f"Reconstruction from first {m} shares: {'✓ SUCCESS' if ok else '✗ FAILED'}",
               style={"color": GREEN if ok else RED, "fontWeight": "bold"}),
    ]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [SentinelVault] %(levelname)s — %(message)s")
    port = int(os.getenv("SENTINEL_PORT", "8090"))
    debug = os.getenv("SENTINEL_DEBUG", "0") == "1"
    print(f"\n🛡️  SentinelVault Dashboard → http://localhost:{port}\n")
    app.run(debug=debug, host="0.0.0.0", port=port)
