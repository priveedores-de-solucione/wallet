from __future__ import annotations

import os, json, re, secrets, hashlib, base64, time
from typing import Literal, Optional
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta

from pydantic import BaseModel
import base58
import nacl.signing
import nacl.exceptions
from stellar_sdk import Keypair as StellarKeypair
from mnemonic import Mnemonic as BIP39
from fastapi import FastAPI, HTTPException, Depends, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jose import jwt, JWTError
from eth_account import Account
from mnemonic import Mnemonic
from supabase import create_client, Client
import aiohttp
from solders.keypair import Keypair as SolanaKeypair
import hashlib, hmac, struct

load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────

ENCRYPTION_KEY    = bytes.fromhex(os.environ["WALLET_ENC_KEY"])
JWT_SECRET        = os.environ["JWT_SECRET"]
JWT_ALGORITHM     = "HS256"
JWT_EXPIRE_HOURS  = 720  # 30 days

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
BACKEND_URL  = os.getenv("BACKEND_URL",  "http://localhost:8000")

SUPABASE_URL         = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
SUPABASE_ANON_KEY    = os.getenv("SUPABASE_ANON_KEY", "")

SUPABASE_AUTH_URL = SUPABASE_URL

# Admin key for one-off maintenance endpoints (e.g. profile email backfill)
ADMIN_KEY = os.getenv("ADMIN_KEY", "")

# ── Multi-project Supabase auth ─────────────────────────────────────────────
# Tokens are verified by the Supabase project that issued them. Add other
# apps' projects (e.g. BCL-onchain) via EXTRA_SUPABASE_PROJECTS, a JSON object
# of {"<project url>": "<that project's anon key>"}.
import json as _json

SUPABASE_PROJECTS: dict[str, str] = {
    SUPABASE_URL.rstrip("/"): SUPABASE_SERVICE_KEY,
}
try:
    SUPABASE_PROJECTS.update({
        u.rstrip("/"): k
        for u, k in _json.loads(os.getenv("EXTRA_SUPABASE_PROJECTS", "{}")).items()
    })
    print("[supabase-projects]", list(SUPABASE_PROJECTS))
except ValueError as _e:
    raise RuntimeError(f"EXTRA_SUPABASE_PROJECTS is not valid JSON: {_e}")


def _pick_supabase_project(token: str) -> tuple[str, str]:
    """Return (project_base_url, apikey) for the project that issued `token`."""
    try:
        iss = jwt.get_unverified_claims(token).get("iss", "")
    except JWTError:
        raise HTTPException(401, "Malformed Supabase token")
    base = iss.removesuffix("/auth/v1").rstrip("/")
    key = SUPABASE_PROJECTS.get(base)
    if not key:
        print(f"[supabase-project] iss={iss!r} base={base!r} allowed={list(SUPABASE_PROJECTS)}")
        raise HTTPException(401, "Supabase project not allowed")
    return base, key

# ── PIN / security-question tuning ──────────────────────────────────────────
PIN_GRANT_TTL_SECONDS         = int(os.getenv("PIN_GRANT_TTL_SECONDS", "120"))
PIN_RESET_GRANT_TTL_SECONDS   = int(os.getenv("PIN_RESET_GRANT_TTL_SECONDS", "600"))
PIN_MAX_ATTEMPTS              = int(os.getenv("PIN_MAX_ATTEMPTS", "5"))
PIN_LOCKOUT_SECONDS           = int(os.getenv("PIN_LOCKOUT_SECONDS", "300"))
SECURITY_QA_MAX_ATTEMPTS      = int(os.getenv("SECURITY_QA_MAX_ATTEMPTS", "5"))
SECURITY_QA_LOCKOUT_SECONDS   = int(os.getenv("SECURITY_QA_LOCKOUT_SECONDS", "900"))
SECURITY_QUESTIONS_MIN_COUNT  = int(os.getenv("SECURITY_QUESTIONS_MIN_COUNT", "3"))

# ─────────────────────────────────────────────────────────────────────────────
# Supabase client + provider sets
# ─────────────────────────────────────────────────────────────────────────────

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# Providers whose tokens are validated via Supabase /auth/v1/user.
# "passkey" is included here — Supabase issues a real access_token after
# WebAuthn authentication, so it follows the exact same server-side path
# as OAuth providers.  The frontend uses supabase.auth.signInWithPasskey()
# / supabase.auth.enrollPasskey() and sends the resulting access_token.
SUPABASE_OAUTH_PROVIDERS = {
    "google", "github", "discord", "twitter", "facebook",
    "apple", "azure", "bitbucket", "gitlab", "figma",
    "kakao", "keycloak", "linkedin", "notion", "slack",
    "spotify", "twitch", "workos", "zoom",
    "passkey",   # ← Supabase WebAuthn; same token-verification path as OAuth
}

# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

SocialProvider = Literal[
    # ── Supabase-native OAuth + WebAuthn ──────────────────────────────────
    "google", "github", "discord", "twitter", "facebook",
    "apple", "azure", "bitbucket", "gitlab", "figma",
    "kakao", "keycloak", "linkedin", "notion", "slack",
    "spotify", "twitch", "workos", "zoom",
    "passkey",
    # ── Custom / non-OAuth ────────────────────────────────────────────────
    "telegram", "farcaster", "phone",
]

class ExternalLoginRequest(BaseModel):
    address: str

class ClearPinRequest(BaseModel):
    reset_grant: str

class SocialLoginRequest(BaseModel):
    provider:       SocialProvider
    # For all Supabase providers (OAuth + passkey):
    supabase_token: str | None = None   # access_token from supabase.auth.getSession()
    # For non-Supabase providers (telegram / farcaster):
    credential:     str | None = None

class LinkSocialRequest(BaseModel):
    provider:       SocialProvider
    supabase_token: str | None = None
    credential:     str | None = None

class ImportPrivySeedRequest(BaseModel):
    mnemonic: str

class WalletResponse(BaseModel):
    address:              str
    token:                str
    linked_socials:       list[str]
    evm_address:          str | None = None
    solana_address:       str | None = None
    stellar_address:      str | None = None
    legacy_found:         bool = False
    legacy_privy_id:      str | None = None
    legacy_evm_address:   str | None = None
    legacy_sol_address:   str | None = None
    needs_seed_import:    bool = False
    has_pin:              bool = False

class LinkExternalAddressRequest(BaseModel):
    chain:     Literal["solana", "stellar"]
    address:   str
    message:   str
    signature: str

# ── PIN / security-question request models ──────────────────────────────────

class SetPinRequest(BaseModel):
    pin:          str
    current_pin:  str | None = None
    reset_grant:  str | None = None

class VerifyPinRequest(BaseModel):
    pin: str

class SecurityQAItem(BaseModel):
    question: str
    answer:   str

class SetSecurityQuestionsRequest(BaseModel):
    items:       list[SecurityQAItem]
    current_pin: str | None = None

class VerifySecurityAnswersRequest(BaseModel):
    answers: list[SecurityQAItem]

class ResetPinRequest(BaseModel):
    pin:         str
    reset_grant: str

class ExportKeyRequest(BaseModel):
    chain_id:      int
    signing_grant: str

class SendOtpRequest(BaseModel):
    phone_number: str   # E.164 format, e.g. "+2348012345678"

class VerifyOtpRequest(BaseModel):
    phone_number: str
    code:         str

class LinkPhoneRequest(BaseModel):
    phone_number: str
    code:         str

# ── Passkey signing grant ────────────────────────────────────────────────────

class PasskeySigningRequest(BaseModel):
    supabase_token: str   # fresh access_token from passkey re-authentication

# ─────────────────────────────────────────────────────────────────────────────
# Crypto helpers — mnemonic / wallet derivation
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_mnemonic(mnemonic: str) -> str:
    aesgcm = AESGCM(ENCRYPTION_KEY)
    nonce  = secrets.token_bytes(12)
    ct     = aesgcm.encrypt(nonce, mnemonic.encode(), None)
    return base64.b64encode(nonce + ct).decode()

def decrypt_mnemonic(blob: str) -> str:
    raw       = base64.b64decode(blob)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(ENCRYPTION_KEY).decrypt(nonce, ct, None).decode()

def derive_wallet(mnemonic: str, account_index: int = 0) -> tuple[str, str]:
    Account.enable_unaudited_hdwallet_features()
    acct = Account.from_mnemonic(
        mnemonic, account_path=f"m/44'/60'/0'/0/{account_index}"
    )
    return acct.address, acct.key.hex()

def create_wallet_for_user() -> tuple[str, str, str, str, str]:
    """Returns (evm_address, encrypted_mnemonic, mnemonic, solana_address, stellar_address)"""
    phrase = Mnemonic("english").generate(strength=128)
    evm_address, _ = derive_wallet(phrase)
    sol_address, _ = derive_solana_address(phrase)
    xlm_address, _ = derive_stellar_address(phrase)
    return evm_address.lower(), encrypt_mnemonic(phrase), phrase, sol_address, xlm_address

def _mnemonic_to_seed(mnemonic: str) -> bytes:
    return Mnemonic.to_seed(mnemonic)

def _derive_ed25519(seed: bytes, path: str) -> bytes:
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = I[:32], I[32:]
    for segment in path.strip("m/").split("/"):
        hardened = segment.endswith("'")
        index    = int(segment.rstrip("'")) + (0x80000000 if hardened else 0)
        data     = b"\x00" + key + struct.pack(">I", index)
        I        = hmac.new(chain, data, hashlib.sha512).digest()
        key, chain = I[:32], I[32:]
    return key

def derive_solana_address(mnemonic: str) -> tuple[str, str]:
    seed    = _mnemonic_to_seed(mnemonic)
    privkey = _derive_ed25519(seed, "m/44'/501'/0'/0'")
    kp      = SolanaKeypair.from_seed(privkey)
    return str(kp.pubkey()), kp.secret().hex()

def derive_stellar_address(mnemonic: str) -> tuple[str, str]:
    seed    = _mnemonic_to_seed(mnemonic)
    privkey = _derive_ed25519(seed, "m/44'/148'/0'")
    kp      = StellarKeypair.from_raw_ed25519_seed(privkey)
    return kp.public_key, kp.secret

# ─────────────────────────────────────────────────────────────────────────────
# Crypto helpers — PIN / security-answer hashing (PBKDF2, salted, constant-time)
# ─────────────────────────────────────────────────────────────────────────────

def _hash_pin(pin: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, 200_000)
    return base64.b64encode(dk).decode()

def hash_pin_for_storage(pin: str) -> str:
    salt   = secrets.token_bytes(16)
    digest = _hash_pin(pin, salt)
    return f"{base64.b64encode(salt).decode()}:{digest}"

def verify_pin_hash(pin: str, stored: str) -> bool:
    try:
        salt_b64, digest = stored.split(":", 1)
        salt = base64.b64decode(salt_b64)
        return hmac.compare_digest(_hash_pin(pin, salt), digest)
    except Exception:
        return False

def _normalize_answer(answer: str) -> str:
    return answer.strip().lower()

def hash_answer_for_storage(answer: str) -> str:
    return hash_pin_for_storage(_normalize_answer(answer))

def verify_answer_hash(answer: str, stored: str) -> bool:
    return verify_pin_hash(_normalize_answer(answer), stored)

# ─────────────────────────────────────────────────────────────────────────────
# JWT helpers — session tokens
# ─────────────────────────────────────────────────────────────────────────────

def create_token(address: str) -> str:
    payload = {
        "sub": address.lower(),
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRE_HOURS * 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

bearer = HTTPBearer()

def get_current_address(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
) -> str:
    return verify_token(creds.credentials)

# ─────────────────────────────────────────────────────────────────────────────
# JWT helpers — short-lived grants (signing grant + PIN-reset grant)
# ─────────────────────────────────────────────────────────────────────────────

def create_signing_grant(address: str) -> str:
    payload = {
        "sub":     address.lower(),
        "purpose": "sign_grant",
        "jti":     secrets.token_urlsafe(16),
        "iat":     int(time.time()),
        "exp":     int(time.time()) + PIN_GRANT_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def consume_signing_grant(token: str, expected_address: str) -> None:
    """Validates the signing grant AND atomically marks it used."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(401, "Signing grant expired or invalid — re-enter your PIN")

    if payload.get("purpose") != "sign_grant":
        raise HTTPException(401, "Invalid signing grant")
    if payload.get("sub") != expected_address.lower():
        raise HTTPException(401, "Signing grant does not match authenticated wallet")

    jti = payload.get("jti")
    if not jti:
        raise HTTPException(401, "Malformed signing grant")

    try:
        supabase.table("used_signing_grants").insert({
            "jti":        jti,
            "expires_at": payload["exp"],
        }).execute()
    except Exception:
        raise HTTPException(401, "Signing grant already used")

def create_pin_reset_grant(address: str) -> str:
    payload = {
        "sub":     address.lower(),
        "purpose": "pin_reset",
        "iat":     int(time.time()),
        "exp":     int(time.time()) + PIN_RESET_GRANT_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_pin_reset_grant(token: str, expected_address: str) -> None:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(401, "Reset session expired — please answer your security questions again")
    if payload.get("purpose") != "pin_reset":
        raise HTTPException(401, "Invalid reset grant")
    if payload.get("sub") != expected_address.lower():
        raise HTTPException(401, "Reset grant does not match authenticated wallet")

# ─────────────────────────────────────────────────────────────────────────────
# DB helpers — wallets / socials
# ─────────────────────────────────────────────────────────────────────────────

def db_get_wallet(address: str) -> dict | None:
    res = supabase.table("wallets").select("*").eq("address", address.lower()).execute()
    return res.data[0] if res.data else None

def db_get_wallet_by_social(provider: str, uid: str) -> dict | None:
    res = (
        supabase.table("linked_socials")
        .select("address, wallets(*)")
        .eq("provider", provider)
        .eq("uid", uid)
        .execute()
    )
    return res.data[0]["wallets"] if res.data else None

def db_get_linked_socials(address: str) -> list[str]:
    res = (
        supabase.table("linked_socials")
        .select("provider")
        .eq("address", address.lower())
        .execute()
    )
    return list({r["provider"] for r in (res.data or [])})

def db_create_wallet(address: str, wallet_type: str, encrypted_mnemonic: str | None,
                     solana_address: str | None = None, stellar_address: str | None = None) -> dict:
    res = supabase.table("wallets").insert({
        "address":            address.lower(),
        "wallet_type":        wallet_type,
        "encrypted_mnemonic": encrypted_mnemonic,
        "solana_address":     solana_address,
        "stellar_address":    stellar_address,
    }).execute()
    return res.data[0]

def db_get_linked_socials_with_handles(address: str) -> list[dict]:
    res = (
        supabase.table("linked_socials")
        .select("provider, uid, handle")
        .eq("address", address.lower())
        .execute()
    )
    return res.data or []

# ─────────────────────────────────────────────────────────────────────────────
# DB helpers — PIN storage + lockout
# ─────────────────────────────────────────────────────────────────────────────

def db_set_wallet_pin(address: str, pin_hash: str):
    supabase.table("wallets").update({
        "pin_hash":          pin_hash,
        "pin_failed_count":  0,
        "pin_locked_until":  None,
    }).eq("address", address.lower()).execute()

def db_record_pin_failure(address: str, current_failures: int):
    new_count = current_failures + 1
    update = {"pin_failed_count": new_count}
    if new_count >= PIN_MAX_ATTEMPTS:
        update["pin_locked_until"] = (
            datetime.now(timezone.utc) + timedelta(seconds=PIN_LOCKOUT_SECONDS)
        ).isoformat()
    supabase.table("wallets").update(update).eq("address", address.lower()).execute()

def db_reset_pin_failures(address: str):
    supabase.table("wallets").update({
        "pin_failed_count": 0, "pin_locked_until": None,
    }).eq("address", address.lower()).execute()

def _pin_lock_active(wallet: dict) -> bool:
    locked_until = wallet.get("pin_locked_until")
    if not locked_until:
        return False
    try:
        return datetime.fromisoformat(locked_until) > datetime.now(timezone.utc)
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# DB helpers — security questions storage + lockout
# ─────────────────────────────────────────────────────────────────────────────

def db_set_security_questions(address: str, items: list[dict]):
    supabase.table("wallets").update({
        "security_questions":    json.dumps(items),
        "security_failed_count": 0,
        "security_locked_until": None,
    }).eq("address", address.lower()).execute()

def db_get_security_questions(wallet: dict) -> list[dict] | None:
    raw = wallet.get("security_questions")
    if not raw:
        return None
    try:
        return json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return None

def db_record_security_failure(address: str, current_failures: int):
    new_count = current_failures + 1
    update = {"security_failed_count": new_count}
    if new_count >= SECURITY_QA_MAX_ATTEMPTS:
        update["security_locked_until"] = (
            datetime.now(timezone.utc) + timedelta(seconds=SECURITY_QA_LOCKOUT_SECONDS)
        ).isoformat()
    supabase.table("wallets").update(update).eq("address", address.lower()).execute()

def db_reset_security_failures(address: str):
    supabase.table("wallets").update({
        "security_failed_count": 0, "security_locked_until": None,
    }).eq("address", address.lower()).execute()

def _security_lock_active(wallet: dict) -> bool:
    locked_until = wallet.get("security_locked_until")
    if not locked_until:
        return False
    try:
        return datetime.fromisoformat(locked_until) > datetime.now(timezone.utc)
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# DB helpers — linked_socials
# ─────────────────────────────────────────────────────────────────────────────

def db_link_social(address: str, provider: str, uid: str, handle: str | None = None):
    try:
        supabase.table("linked_socials").insert({
            "address":  address.lower(),
            "provider": provider,
            "uid":      uid,
            "handle":   handle,
        }).execute()
    except Exception:
        raise HTTPException(
            409,
            f"This {provider} account is already linked to a different wallet.",
        )

# ─────────────────────────────────────────────────────────────────────────────
# DB helpers — cross-provider wallet lookup
# ─────────────────────────────────────────────────────────────────────────────

def db_get_wallet_by_any_supabase_identity(
    identities: list[dict],
) -> tuple[dict | None, str | None, str | None]:
    """
    Check linked_socials for any (provider, uid) pair that already has a wallet.
    Also does a cross-provider search by Supabase user UUID alone, since all
    Supabase-managed providers store uid = Supabase user UUID.
    """
    # Collect all UIDs to search — for Supabase providers, uid IS the Supabase user UUID
    # so the same UUID may appear under google, github, passkey, etc.
    supabase_uids = {i.get("id", "") for i in identities if i.get("id")}

    # Cross-provider scan: find any linked_socials row whose uid matches any
    # Supabase user UUID from this account, across all SUPABASE_OAUTH_PROVIDERS
    if supabase_uids:
        res = (
            supabase.table("linked_socials")
            .select("address, provider, uid, wallets(*)")
            .in_("uid", list(supabase_uids))
            .in_("provider", list(SUPABASE_OAUTH_PROVIDERS))
            .execute()
        )
        if res.data:
            row = res.data[0]
            wallet = row.get("wallets")
            if wallet:
                return wallet, row.get("provider"), row.get("uid")

    # Per-identity fallback (covers telegram, farcaster whose uid ≠ Supabase UUID)
    for identity in identities:
        provider = identity.get("provider", "")
        uid      = identity.get("id", "")
        if not provider or not uid or provider == "__supabase_uid__":
            continue
        wallet = db_get_wallet_by_social(provider, uid)
        if wallet:
            return wallet, provider, uid

    return None, None, None

# ─────────────────────────────────────────────────────────────────────────────
# DB helpers — legacy Privy lookups
# ─────────────────────────────────────────────────────────────────────────────

def db_find_legacy_by_social(provider: str, uid: str, handle: str | None = None) -> dict | None:
    if provider == "telegram":
        res = (
            supabase.table("legacy_privy_users")
            .select("*")
            .eq("telegram_id", uid)
            .eq("claimed", False)
            .limit(1)
            .execute()
        )
        return res.data[0] if res.data else None

    if provider == "farcaster":
        res = (
            supabase.table("legacy_privy_users")
            .select("*")
            .eq("farcaster_id", uid)
            .eq("claimed", False)
            .limit(1)
            .execute()
        )
        return res.data[0] if res.data else None

    if not handle:
        return None

    normalized = handle.lower().lstrip("@")

    if provider == "google":
        res = (
            supabase.table("legacy_privy_users")
            .select("*")
            .ilike("google_email", normalized)
            .eq("claimed", False)
            .limit(1)
            .execute()
        )
        if res.data:
            return res.data[0]
        res = (
            supabase.table("legacy_privy_users")
            .select("*")
            .ilike("email", normalized)
            .eq("claimed", False)
            .limit(1)
            .execute()
        )
        return res.data[0] if res.data else None

    col_map = {
        "twitter": "twitter_handle",
        "discord": "discord_handle",
        "github":  "github_handle",
    }
    col = col_map.get(provider)
    if not col:
        return None

    res = (
        supabase.table("legacy_privy_users")
        .select("*")
        .ilike(col, normalized)
        .eq("claimed", False)
        .limit(1)
        .execute()
    )
    return res.data[0] if res.data else None

def db_find_claimed_legacy_wallet(
    provider: str, uid: str, handle: str | None = None
) -> dict | None:
    """
    For returning users whose linked_socials row is missing (e.g. new Supabase UID
    after a cookie wipe), find a *claimed* legacy row that matches by handle/uid
    and return the wallet that was linked to it.
    """
    col_uid_map = {
        "telegram":  "telegram_id",
        "farcaster": "farcaster_id",
    }
    col_uid = col_uid_map.get(provider)
    if col_uid:
        res = (
            supabase.table("legacy_privy_users")
            .select("embedded_evm_address")
            .eq(col_uid, uid)
            .eq("claimed", True)
            .limit(1)
            .execute()
        )
        if res.data and res.data[0].get("embedded_evm_address"):
            return db_get_wallet(res.data[0]["embedded_evm_address"])

    if not handle:
        return None

    normalized = handle.lower().lstrip("@")

    if provider == "google":
        for col in ("google_email", "email"):
            res = (
                supabase.table("legacy_privy_users")
                .select("embedded_evm_address")
                .ilike(col, normalized)
                .eq("claimed", True)
                .limit(1)
                .execute()
            )
            if res.data and res.data[0].get("embedded_evm_address"):
                return db_get_wallet(res.data[0]["embedded_evm_address"])
        return None

    col_handle_map = {
        "twitter": "twitter_handle",
        "discord": "discord_handle",
        "github":  "github_handle",
    }
    col = col_handle_map.get(provider)
    if not col:
        return None

    res = (
        supabase.table("legacy_privy_users")
        .select("embedded_evm_address")
        .ilike(col, normalized)
        .eq("claimed", True)
        .limit(1)
        .execute()
    )
    if res.data and res.data[0].get("embedded_evm_address"):
        return db_get_wallet(res.data[0]["embedded_evm_address"])
    return None

def db_mark_legacy_claimed(legacy_id: str, wallet_address: str):
    supabase.table("legacy_privy_users").update({
        "claimed":    True,
        "claimed_at": datetime.now(timezone.utc).isoformat(),
    }).eq("id", legacy_id).execute()

    supabase.table("wallets").update({
        "legacy_import_completed": True,
    }).eq("address", wallet_address.lower()).execute()

# ─────────────────────────────────────────────────────────────────────────────
# Supabase token resolver — shared by all SUPABASE_OAUTH_PROVIDERS + passkey
# ─────────────────────────────────────────────────────────────────────────────

def _profile_meta_from_user(provider: str, user_data: dict) -> tuple[str | None, dict]:
    """
    Builds (handle, profile_meta) from a Supabase user object.
    Uses the identity that matches `provider` — NOT identities[0], which is
    whichever provider the user linked first (e.g. Twitter when linking Google).
    """
    identities = user_data.get("identities") or []
    wanted = {"twitter", "x"} if provider == "twitter" else {provider}
    match  = next((i for i in identities if i.get("provider") in wanted), None)
    if match is None and identities:
        # Fallback: the most recently linked identity
        match = max(identities, key=lambda i: i.get("created_at") or "")
    id_data = (match or {}).get("identity_data", {}) or {}

    handle = (
        id_data.get("email")
        or id_data.get("preferred_username")
        or id_data.get("user_name")
        or id_data.get("login")
        or id_data.get("name")
        or id_data.get("username")
        or user_data.get("email")
    )

    profile_meta = {
        "email":        id_data.get("email") or user_data.get("email"),
        "avatar_url": (
            id_data.get("avatar_url")
            or id_data.get("picture")
            or id_data.get("profile_image_url")
        ),
        "display_name": (
            id_data.get("full_name")
            or id_data.get("name")
            or id_data.get("login")
            or id_data.get("username")
            or id_data.get("preferred_username")
        ),
        "twitter_handle":  (id_data.get("preferred_username") or id_data.get("user_name")) if provider == "twitter" else None,
        "discord_handle":  id_data.get("username")                                         if provider == "discord" else None,
        "github_handle":   (id_data.get("login") or id_data.get("user_name"))              if provider == "github" else None,
        "linkedin_handle": id_data.get("preferred_username")                               if provider == "linkedin" else None,
        "notion_handle":   id_data.get("name")                                             if provider == "notion" else None,
    }
    return handle, profile_meta


async def resolve_supabase_provider_uid(
    provider: str, supabase_access_token: str
) -> tuple[str, str | None, dict, list[dict]]:
    """
    Validates a Supabase access_token and returns:
        (uid, handle, profile_meta, normalized_identities)

    normalized_identities is used for cross-provider wallet lookup — it maps
    every identity on this Supabase account to (provider, id) so that
    get_or_create_wallet can find an existing wallet even when the user logs
    in with a different provider than the one they originally registered with.
    """
    base, api_key = _pick_supabase_project(supabase_access_token)
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{base}/auth/v1/user",
            headers={
                "apikey":        api_key,
                "Authorization": f"Bearer {supabase_access_token}",
            },
        ) as resp:
            if resp.status != 200:
                body = await resp.json()
                detail = body.get("msg") or body.get("message") or "Invalid Supabase token"
                raise HTTPException(401, detail)
            user_data = await resp.json()

    uid = user_data.get("id")
    if not uid:
        raise HTTPException(500, "Supabase returned no user ID")

    handle, profile_meta = _profile_meta_from_user(provider, user_data)

    # Normalized identity list for cross-provider lookup.
    # Supabase uses "x" for Twitter internally; we store "twitter".
    # "email" provider entries (email/password) are not wallet login methods — skip.
    normalized_identities: list[dict] = [{
        "provider": "__supabase_uid__",   # sentinel — only used for cross-lookup
        "id": uid,
    }]

    for ident in user_data.get("identities") or []:
        raw_p = ident.get("provider", "")
        if raw_p == "email":
            continue
        normalized_identities.append({
            "provider": "twitter" if raw_p == "x" else raw_p,
            "id":       ident.get("id", ""),
        })

    return uid, handle, profile_meta, normalized_identities

# ─────────────────────────────────────────────────────────────────────────────
# Core: get-or-create wallet
# ─────────────────────────────────────────────────────────────────────────────

def _backfill_chain_addresses(wallet: dict) -> dict:
    """
    If an embedded wallet is missing Stellar or Solana addresses, derive and
    persist them from the stored mnemonic.  Returns the (possibly mutated) wallet.
    """
    if not (wallet.get("encrypted_mnemonic") and not wallet.get("stellar_address")):
        return wallet
    try:
        mnemonic       = decrypt_mnemonic(wallet["encrypted_mnemonic"])
        xlm_address, _ = derive_stellar_address(mnemonic)
        sol_address, _ = derive_solana_address(mnemonic)
        supabase.table("wallets").update({
            "stellar_address": xlm_address,
            "solana_address":  sol_address,
        }).eq("address", wallet["address"]).execute()
        wallet["stellar_address"] = xlm_address
        wallet["solana_address"]  = sol_address
    except Exception:
        pass
    return wallet


def get_or_create_wallet(
    provider:            SocialProvider,
    uid:                 str,
    handle:              str | None = None,
    supabase_identities: list[dict] | None = None,
) -> tuple[dict, dict | None]:
    """
    Resolves or creates the wallet for a given (provider, uid) pair.

    Resolution order:
      1. Fast path  — exact (provider, uid) match in linked_socials
      2. Cross-provider — same Supabase account with a different already-linked provider
      3. Unclaimed legacy Privy record
      4. Previously-claimed legacy (prevents duplicate wallets after cookie wipe)
      5. Brand-new wallet generation
    """

    # ── 1. Fast path ─────────────────────────────────────────────────────────
    existing = db_get_wallet_by_social(provider, uid)
    if existing:
        legacy = None
        if not existing.get("legacy_import_completed"):
            legacy = db_find_legacy_by_social(provider, uid, handle)
        existing = _backfill_chain_addresses(existing)
        return existing, legacy

    # ── 2. Cross-provider lookup ──────────────────────────────────────────────
    if supabase_identities:
        cross_wallet, matched_provider, matched_uid = db_get_wallet_by_any_supabase_identity(
            supabase_identities
        )
        if cross_wallet:
            try:
                db_link_social(cross_wallet["address"], provider, uid, handle=handle)
            except HTTPException:
                pass  # already linked — benign race condition
            cross_wallet = _backfill_chain_addresses(cross_wallet)
            return cross_wallet, None

    # ── 3. Unclaimed legacy Privy record ──────────────────────────────────────
    legacy = db_find_legacy_by_social(provider, uid, handle)

    if legacy and legacy.get("embedded_evm_address"):
        legacy_evm = legacy["embedded_evm_address"].lower()
        legacy_sol = legacy.get("embedded_solana_address")

        other = db_get_wallet_by_social(provider, uid)
        if other and other["address"] != legacy_evm:
            raise HTTPException(
                409,
                f"This {provider} account is already linked to a different wallet.",
            )

        wallet = db_get_wallet(legacy_evm) or db_create_wallet(
            legacy_evm, "embedded", None,
            solana_address=legacy_sol,
            stellar_address=None,
        )
        db_link_social(legacy_evm, provider, uid, handle=handle)
        return wallet, legacy

    # ── 4. Previously-claimed legacy (prevents duplicate wallets) ─────────────
    recovered = db_find_claimed_legacy_wallet(provider, uid, handle)
    if recovered:
        try:
            db_link_social(recovered["address"], provider, uid, handle=handle)
        except HTTPException:
            pass
        return recovered, None

    # ── 5. Brand-new wallet ───────────────────────────────────────────────────
    evm_address, encrypted_mnemonic, _, sol_address, xlm_address = create_wallet_for_user()
    wallet = db_create_wallet(
        evm_address, "embedded", encrypted_mnemonic,
        solana_address=sol_address,
        stellar_address=xlm_address,
    )

    other = db_get_wallet_by_social(provider, uid)
    if other and other["address"] != evm_address:
        raise HTTPException(
            409,
            f"This {provider} account is already linked to a different wallet.",
        )

    db_link_social(evm_address, provider, uid, handle=handle)
    return wallet, legacy

# ─────────────────────────────────────────────────────────────────────────────
# Profile upsert
# ─────────────────────────────────────────────────────────────────────────────

def _email_taken_by_other(email: str, wallet: str) -> bool:
    res = (
        supabase.table("user_profiles")
        .select("wallet_address")
        .eq("email", email)
        .execute()
    )
    return any((r.get("wallet_address") or "").lower() != wallet for r in (res.data or []))


def upsert_profile_from_social(evm_address: str, provider: str, profile_meta: dict):
    """
    Called after every social login / link.
    Fills missing fields only — never overwrites a user's manual edits.
    Linking Google (or any provider with an email) sets the profile email
    when the profile has none, unless another profile already uses it.
    """
    wallet = evm_address.lower()
    email  = (profile_meta.get("email") or "").strip().lower()

    existing = (
        supabase.table("user_profiles")
        .select("*")
        .eq("wallet_address", wallet)
        .execute()
    )

    if existing.data:
        row   = existing.data[0]
        patch = {}

        if email and not row.get("email"):
            if _email_taken_by_other(email, wallet):
                print(f"[profile-upsert] {email} already used by another profile — not linking to {wallet}")
            else:
                patch["email"] = email

        if not row.get("avatar_url") and profile_meta.get("avatar_url"):
            patch["avatar_url"] = profile_meta["avatar_url"]

        for field in ("twitter_handle", "discord_handle", "github_handle",
                      "linkedin_handle", "notion_handle"):
            if profile_meta.get(field):
                patch[field] = profile_meta[field]

        if patch:
            patch["updated_at"] = datetime.now(timezone.utc).isoformat()
            supabase.table("user_profiles").update(patch).eq("wallet_address", wallet).execute()
            print(f"[profile-upsert] {wallet} via {provider}: updated {list(patch)}")

    else:
        base_name = (
            profile_meta.get("display_name")
            or profile_meta.get("twitter_handle")
            or profile_meta.get("discord_handle")
            or profile_meta.get("github_handle")
            or f"user_{wallet[-6:]}"
        )
        base_name = re.sub(r"[^a-z0-9_]", "_", base_name.lower())[:30]

        username = base_name
        if supabase.table("user_profiles").select("username").eq("username", username).execute().data:
            username = f"{base_name}_{wallet[-4:]}"

        safe_email = email if email and not _email_taken_by_other(email, wallet) else None

        supabase.table("user_profiles").insert({
            "wallet_address":   wallet,
            "username":         username,
            "email":            safe_email,   # None, never "" — avoids unique-constraint clashes
            "avatar_url":       profile_meta.get("avatar_url") or "",
            "twitter_handle":   profile_meta.get("twitter_handle"),
            "discord_handle":   profile_meta.get("discord_handle"),
            "github_handle":    profile_meta.get("github_handle"),
            "linkedin_handle":  profile_meta.get("linkedin_handle"),
            "notion_handle":    profile_meta.get("notion_handle"),
            "updated_at":       datetime.now(timezone.utc).isoformat(),
        }).execute()

# ─────────────────────────────────────────────────────────────────────────────
# Profile backfill from already-linked socials
# ─────────────────────────────────────────────────────────────────────────────

PROFILE_SYNC_ORDER = ["google", "github", "discord", "twitter", "linkedin", "notion"]

async def fetch_supabase_user_admin(uid: str) -> dict | None:
    """Reads a Supabase user (with identities) from the main project using the service key."""
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{SUPABASE_URL}/auth/v1/admin/users/{uid}",
            headers=_supabase_auth_headers(),
        ) as resp:
            if resp.status != 200:
                return None
            return await resp.json()


async def sync_profile_from_linked_socials(address: str) -> bool:
    """
    If the profile has no email, pull it (plus handles/avatar) from the
    wallet's already-linked Supabase socials — Google first.
    Returns True if a sync was attempted.
    """
    address = address.lower()

    prof = (
        supabase.table("user_profiles")
        .select("email")
        .eq("wallet_address", address)
        .execute()
    )
    if prof.data and prof.data[0].get("email"):
        return False

    rows = [
        r for r in db_get_linked_socials_with_handles(address)
        if r["provider"] in SUPABASE_OAUTH_PROVIDERS and r["provider"] != "passkey"
    ]
    rows.sort(key=lambda r: PROFILE_SYNC_ORDER.index(r["provider"])
              if r["provider"] in PROFILE_SYNC_ORDER else 99)

    user_cache: dict[str, dict | None] = {}
    for row in rows:
        uid = row["uid"]
        if uid not in user_cache:
            user_cache[uid] = await fetch_supabase_user_admin(uid)
        user = user_cache[uid]
        if not user:
            continue
        _, meta = _profile_meta_from_user(row["provider"], user)
        upsert_profile_from_social(address, row["provider"], meta)

    return True

# ─────────────────────────────────────────────────────────────────────────────
# External wallet registration + social linking helpers
# ─────────────────────────────────────────────────────────────────────────────

def register_external_wallet(address: str) -> dict:
    address  = address.lower()
    existing = db_get_wallet(address)
    return existing if existing else db_create_wallet(address, "external", None)

def link_social_to_wallet(
    address:             str,
    provider:            SocialProvider,
    uid:                 str,
    handle:              str | None = None,
    supabase_identities: list[dict] | None = None,
):
    """
    Links a social provider to an existing authenticated wallet.
    supabase_identities is accepted (and ignored here) to keep the call-site
    signature consistent — cross-provider resolution only applies at login time.
    """
    address  = address.lower()
    existing = db_get_wallet_by_social(provider, uid)
    if existing and existing["address"] != address:
        raise HTTPException(
            status_code=409,
            detail=f"This {provider} account is already linked to a different wallet.",
        )
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found. Connect your wallet first.")
    db_link_social(address, provider, uid, handle=handle)

# ─────────────────────────────────────────────────────────────────────────────
# Phone OTP helpers (Supabase Phone Auth)
# ─────────────────────────────────────────────────────────────────────────────

def _supabase_auth_headers() -> dict:
    return {
        "apikey":        SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "Content-Type":  "application/json",
    }

async def send_otp(phone_number: str) -> None:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SUPABASE_URL}/auth/v1/otp",
            headers=_supabase_auth_headers(),
            json={"phone": phone_number, "channel": "sms"},
        ) as resp:
            if resp.status not in (200, 201, 204):
                body = await resp.json()
                detail = body.get("msg") or body.get("message") or "Failed to send OTP"
                raise HTTPException(400, detail)

async def verify_otp(phone_number: str, code: str) -> str:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{SUPABASE_URL}/auth/v1/verify",
            headers=_supabase_auth_headers(),
            json={"phone": phone_number, "token": code, "type": "sms"},
        ) as resp:
            body = await resp.json()
            if resp.status not in (200, 201):
                detail = body.get("msg") or body.get("message") or "Invalid or expired OTP"
                raise HTTPException(401, detail)
            user = body.get("user") or {}
            uid  = user.get("id")
            if not uid:
                raise HTTPException(500, "Phone verification succeeded but no user ID returned")
            return uid

# ─────────────────────────────────────────────────────────────────────────────
# Telegram + Farcaster verification (Supabase doesn't support these natively)
# ─────────────────────────────────────────────────────────────────────────────

def _verify_telegram_login(credential_json: str) -> str:
    bot_token = os.environ["TELEGRAM_BOT_TOKEN"]
    data      = json.loads(credential_json)
    received_hash     = data.pop("hash", "")
    data_check_string = "\n".join(f"{k}={v}" for k, v in sorted(data.items()))
    secret   = hashlib.sha256(bot_token.encode()).digest()
    expected = hmac.new(secret, data_check_string.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, received_hash):
        raise HTTPException(401, "Telegram auth verification failed")
    if time.time() - int(data.get("auth_date", 0)) > 86400:
        raise HTTPException(401, "Telegram auth expired")
    return str(data["id"])

def _verify_farcaster_login(credential: str) -> str:
    try:
        return str(json.loads(credential)["fid"])
    except Exception:
        raise HTTPException(400, "Invalid Farcaster credential")

# ─────────────────────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    Account.enable_unaudited_hdwallet_features()
    yield

app = FastAPI(title="FaucetDrops Wallet Backend", lifespan=lifespan)

ALLOWED_ORIGINS = [
    FRONTEND_URL,
    "http://localhost:3000",
    "https://thoughtful-carmencita-faucetdrops-02a54589.koyeb.app",
    "https://app.faucetdrops.io",
    "https://sigmaprotocol.org",
    "https://www.sigmaprotocol.org",
    "https://faucetdrops.vercel.app",
    "https://agentcombat.xyz",
    "https://www.agentcombat.xyz",
    "https://sigma-protocol.vercel.app",
    "https://www.sigma-protocol.vercel.app",
    "https://blockchainlautech",
    "https://onchain.blockchainlautech.club",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"https://([a-z0-9-]+\.)*(agentcombat\.xyz|faucetdrops\.io|sigmaprotocol\.org|blockchainlautech\.club)",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# External-address linking (Solana / Stellar) + signature verification
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/wallet/link-external-address")
async def link_external_address(
    body:    LinkExternalAddressRequest,
    address: str = Depends(get_current_address),
):
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    if body.chain == "solana":
        _verify_solana_signature(body.address, body.message, body.signature)
        field = "solana_address"
    elif body.chain == "stellar":
        _verify_stellar_signature(body.address, body.message, body.signature)
        field = "stellar_address"
    else:
        raise HTTPException(400, f"Unsupported chain: {body.chain}")

    supabase.table("wallets").update({
        field: body.address,
    }).eq("address", address.lower()).execute()

    return {"success": True, "chain": body.chain, "address": body.address}


def _verify_solana_signature(pubkey_b58: str, message: str, signature_b58: str):
    try:
        pub_bytes = base58.b58decode(pubkey_b58)
        sig_bytes = base58.b58decode(signature_b58)
        msg_bytes = message.encode("utf-8")
        vk = nacl.signing.VerifyKey(pub_bytes)
        vk.verify(msg_bytes, sig_bytes)
    except nacl.exceptions.BadSignatureError:
        raise HTTPException(401, "Solana signature verification failed")
    except Exception as e:
        raise HTTPException(400, f"Invalid Solana signature data: {e}")


def _verify_stellar_signature(public_key: str, message: str, signature_hex: str):
    try:
        kp        = StellarKeypair.from_public_key(public_key)
        msg_bytes = message.encode("utf-8")
        sig_bytes = bytes.fromhex(signature_hex)
        kp.verify(msg_bytes, sig_bytes)
    except Exception:
        raise HTTPException(401, "Stellar signature verification failed")

# ─────────────────────────────────────────────────────────────────────────────
# Core wallet endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/wallet/external-login", response_model=WalletResponse)
async def external_login(body: ExternalLoginRequest):
    wallet = register_external_wallet(body.address)
    token  = create_token(wallet["address"])
    linked = db_get_linked_socials(wallet["address"])
    return WalletResponse(address=wallet["address"], token=token, linked_socials=linked)


@app.post("/wallet/social-login", response_model=WalletResponse)
async def social_login(body: SocialLoginRequest):
    """
    Unified social login endpoint.

    Supabase-managed providers (OAuth + passkey — all in SUPABASE_OAUTH_PROVIDERS):
      - Frontend calls supabase.auth.signInWithOAuth() / signInWithPasskey()
      - Frontend POSTs { provider, supabase_token: session.access_token } here
      - Backend validates via /auth/v1/user and extracts uid, handle, identities

    Non-Supabase providers (telegram, farcaster):
      - Frontend POSTs { provider, credential: <payload> }
      - Backend verifies with its own logic

    Phone login: use /auth/phone/send-otp → /auth/phone/verify-otp.
    """
    supabase_identities: list[dict] | None = None
    profile_meta: dict = {}
    provider = body.provider
    uid:    str
    handle: str | None = None

    if provider == "phone":
        raise HTTPException(
            400,
            "Use /auth/phone/send-otp and /auth/phone/verify-otp for phone login",
        )

    elif provider in SUPABASE_OAUTH_PROVIDERS:
        # Covers all 19 OAuth providers AND passkey
        if not body.supabase_token:
            raise HTTPException(
                400,
                f"supabase_token is required for {provider} login. "
                "Call supabase.auth.getSession() / signInWithPasskey() on the frontend "
                "and pass the access_token.",
            )
        uid, handle, profile_meta, supabase_identities = await resolve_supabase_provider_uid(
            provider, body.supabase_token
        )

    elif provider == "telegram":
        if not body.credential:
            raise HTTPException(400, "credential is required for telegram login")
        uid    = _verify_telegram_login(body.credential)
        handle = None

    elif provider == "farcaster":
        if not body.credential:
            raise HTTPException(400, "credential is required for farcaster login")
        uid    = _verify_farcaster_login(body.credential)
        handle = None

    else:
        raise HTTPException(400, f"Unsupported provider: {provider}")

    wallet, legacy = get_or_create_wallet(
        provider, uid,
        handle=handle,
        supabase_identities=supabase_identities,
    )

    if provider in SUPABASE_OAUTH_PROVIDERS and profile_meta:
        try:
            upsert_profile_from_social(wallet["address"], provider, profile_meta)
        except Exception as e:
            print(f"[profile-upsert] login failed for {provider}: {e}")

    token  = create_token(wallet["address"])
    linked = db_get_linked_socials(wallet["address"])

    return WalletResponse(
        address            = wallet["address"],
        token              = token,
        linked_socials     = linked,
        evm_address        = wallet["address"],
        solana_address     = wallet.get("solana_address"),
        stellar_address    = wallet.get("stellar_address"),
        legacy_found       = legacy is not None,
        legacy_privy_id    = legacy["privy_id"]                    if legacy else None,
        legacy_evm_address = legacy.get("embedded_evm_address")    if legacy else None,
        legacy_sol_address = legacy.get("embedded_solana_address") if legacy else None,
        has_pin            = bool(wallet.get("pin_hash")),
        needs_seed_import  = (
            legacy is not None
            and bool(legacy.get("embedded_evm_address"))
            and not wallet.get("encrypted_mnemonic")
        ),
    )


@app.post("/wallet/link-social")
async def link_social(
    body:    LinkSocialRequest,
    address: str = Depends(get_current_address),
):
    """
    Link an additional social account to an already-authenticated wallet.
    Same provider split as /wallet/social-login.
    """
    supabase_identities: list[dict] | None = None
    profile_meta: dict = {}
    provider = body.provider
    uid:    str
    handle: str | None = None

    if provider == "phone":
        raise HTTPException(400, "Use /wallet/link-phone for phone number linking")

    elif provider in SUPABASE_OAUTH_PROVIDERS:
        if not body.supabase_token:
            raise HTTPException(400, f"supabase_token is required to link {provider}")
        uid, handle, profile_meta, supabase_identities = await resolve_supabase_provider_uid(
            provider, body.supabase_token
        )

    elif provider == "telegram":
        if not body.credential:
            raise HTTPException(400, "credential is required for telegram")
        uid = _verify_telegram_login(body.credential)

    elif provider == "farcaster":
        if not body.credential:
            raise HTTPException(400, "credential is required for farcaster")
        uid = _verify_farcaster_login(body.credential)

    else:
        raise HTTPException(400, f"Unsupported provider: {provider}")

    link_social_to_wallet(
        address, provider, uid,
        handle=handle,
        supabase_identities=supabase_identities,
    )

    if provider in SUPABASE_OAUTH_PROVIDERS and profile_meta:
        try:
            upsert_profile_from_social(address, provider, profile_meta)
        except Exception as e:
            print(f"[profile-upsert] link failed for {provider}: {e}")

    linked = db_get_linked_socials(address)
    return {"success": True, "linked_socials": linked}


@app.get("/wallet/me")
async def get_wallet_me(address: str = Depends(get_current_address)):
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    # Self-heal: fill a missing profile email from already-linked Google etc.
    try:
        await sync_profile_from_linked_socials(address)
    except Exception as e:
        print(f"[profile-sync] /wallet/me failed for {address}: {e}")

    linked = db_get_linked_socials(address)
    return {
        "address":                wallet["address"],
        "wallet_type":            wallet["wallet_type"],
        "linked_socials":         linked,
        "created_at":             wallet["created_at"],
        "has_pin":                bool(wallet.get("pin_hash")),
        "has_security_questions": bool(wallet.get("security_questions")),
    }


@app.post("/admin/backfill-profile-emails")
async def backfill_profile_emails(x_admin_key: str = Header(...)):
    """
    One-off: fill missing profile emails for every wallet that already has
    Google linked. Run once after deploy:
      curl -X POST <backend>/admin/backfill-profile-emails -H "x-admin-key: <ADMIN_KEY>"
    """
    if not ADMIN_KEY or not hmac.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(403, "Forbidden")

    res = (
        supabase.table("linked_socials")
        .select("address")
        .eq("provider", "google")
        .execute()
    )
    addresses = sorted({r["address"] for r in (res.data or [])})

    synced, failed = 0, 0
    for addr in addresses:
        try:
            if await sync_profile_from_linked_socials(addr):
                synced += 1
        except Exception as e:
            failed += 1
            print(f"[backfill] {addr}: {e}")

    return {"checked": len(addresses), "synced": synced, "failed": failed}

# ─────────────────────────────────────────────────────────────────────────────
# Passkey signing grant
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/wallet/passkey-signing-grant")
async def passkey_signing_grant(
    body:    PasskeySigningRequest,
    address: str = Depends(get_current_address),
):
    """
    Issues a signing grant after verifying a *fresh* Supabase passkey session.
    Called instead of /wallet/verify-pin for passkey-secured wallets.

    The frontend must re-authenticate via supabase.auth.signInWithPasskey()
    immediately before calling this endpoint — re-using the login token is
    intentionally rejected because we need proof of physical presence
    (biometric / device PIN) for every transaction signing operation.
    """
    uid, _, _, _ = await resolve_supabase_provider_uid("passkey", body.supabase_token)

    res = (
        supabase.table("linked_socials")
        .select("address")
        .eq("provider", "passkey")
        .eq("uid", uid)
        .eq("address", address.lower())
        .execute()
    )
    if not res.data:
        raise HTTPException(
            403,
            "This passkey is not linked to the authenticated wallet. "
            "Link it first via /wallet/link-social.",
        )

    grant = create_signing_grant(address)
    return {
        "success":       True,
        "signing_grant": grant,
        "expires_in":    PIN_GRANT_TTL_SECONDS,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Import Privy seed phrase
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/wallet/import-privy-seed")
async def import_privy_seed(
    body:    ImportPrivySeedRequest,
    address: str = Depends(get_current_address),
):
    mnemonic = body.mnemonic.strip().lower()
    words    = mnemonic.split()

    if len(words) not in (12, 24):
        raise HTTPException(400, "Seed phrase must be 12 or 24 words")

    bip39 = BIP39("english")
    if not bip39.check(mnemonic):
        raise HTTPException(400, "Invalid BIP-39 seed phrase — check for typos")

    try:
        evm_address, _ = derive_wallet(mnemonic)
        sol_address, _ = derive_solana_address(mnemonic)
        xlm_address, _ = derive_stellar_address(mnemonic)
    except Exception as exc:
        raise HTTPException(400, f"Could not derive wallet from seed: {exc}")

    legacy = None

    linked = db_get_linked_socials_with_handles(address)
    for row in linked:
        legacy = db_find_legacy_by_social(row["provider"], row["uid"], row.get("handle"))
        if legacy:
            break

    if not legacy:
        res = (
            supabase.table("legacy_privy_users")
            .select("*")
            .ilike("embedded_evm_address", evm_address.lower())
            .eq("claimed", False)
            .limit(1)
            .execute()
        )
        legacy = res.data[0] if res.data else None

    if legacy:
        legacy_evm_addrs = {
            (legacy.get("embedded_evm_address") or "").lower(),
            (legacy.get("external_evm_address") or "").lower(),
        } - {""}

        if legacy_evm_addrs and evm_address.lower() not in legacy_evm_addrs:
            raise HTTPException(
                400,
                "This seed phrase doesn't match your Privy account's addresses. "
                "Make sure you exported from the correct Privy account.",
            )

    encrypted = encrypt_mnemonic(mnemonic)
    supabase.table("wallets").update({
        "encrypted_mnemonic":      encrypted,
        "wallet_type":             "embedded",
        "legacy_import_completed": True,
        "legacy_evm_address":      evm_address.lower(),
        "legacy_solana_address":   sol_address,
        "solana_address":          sol_address,
        "stellar_address":         xlm_address,
    }).eq("address", address.lower()).execute()

    if legacy:
        db_mark_legacy_claimed(legacy["id"], address)

    return {
        "success":         True,
        "evm_address":     evm_address,
        "solana_address":  sol_address,
        "stellar_address": xlm_address,
        "legacy_linked":   legacy is not None,
        "message":         "Wallet imported successfully.",
    }

# ─────────────────────────────────────────────────────────────────────────────
# PIN endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/wallet/set-pin")
async def set_pin(body: SetPinRequest, address: str = Depends(get_current_address)):
    if not (body.pin.isdigit() and len(body.pin) == 6):
        raise HTTPException(400, "PIN must be exactly 6 digits")

    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    if wallet.get("pin_hash"):
        if body.reset_grant:
            verify_pin_reset_grant(body.reset_grant, address)
        else:
            if _pin_lock_active(wallet):
                raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")
            if not body.current_pin or not verify_pin_hash(body.current_pin, wallet["pin_hash"]):
                db_record_pin_failure(address, wallet.get("pin_failed_count") or 0)
                raise HTTPException(
                    401,
                    "Current PIN is required and must be correct to change it. "
                    "Forgot it? Verify your security questions instead.",
                )
            db_reset_pin_failures(address)

    db_set_wallet_pin(address, hash_pin_for_storage(body.pin))
    return {"success": True, "message": "PIN set. You'll need it to authorise transactions."}


@app.post("/wallet/verify-pin")
async def verify_pin(body: VerifyPinRequest, address: str = Depends(get_current_address)):
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")
    if not wallet.get("pin_hash"):
        raise HTTPException(400, "No PIN set for this wallet. Call /wallet/set-pin first.")

    if _pin_lock_active(wallet):
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")

    if not verify_pin_hash(body.pin, wallet["pin_hash"]):
        db_record_pin_failure(address, wallet.get("pin_failed_count") or 0)
        raise HTTPException(401, "Incorrect PIN")

    db_reset_pin_failures(address)
    grant = create_signing_grant(address)
    return {
        "success":       True,
        "signing_grant": grant,
        "expires_in":    PIN_GRANT_TTL_SECONDS,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Security question endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/wallet/security-questions/set")
async def set_security_questions(
    body:    SetSecurityQuestionsRequest,
    address: str = Depends(get_current_address),
):
    if len(body.items) < SECURITY_QUESTIONS_MIN_COUNT:
        raise HTTPException(400, f"Please provide at least {SECURITY_QUESTIONS_MIN_COUNT} security questions")

    seen_questions: set[str] = set()
    for item in body.items:
        q = item.question.strip()
        a = item.answer.strip()
        if not q or not a:
            raise HTTPException(400, "Questions and answers cannot be empty")
        if len(a) < 2:
            raise HTTPException(400, "Answers must be at least 2 characters")
        if q.lower() in seen_questions:
            raise HTTPException(400, "Each security question must be unique")
        seen_questions.add(q.lower())

    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    if wallet.get("security_questions") and wallet.get("pin_hash"):
        if not body.current_pin or not verify_pin_hash(body.current_pin, wallet["pin_hash"]):
            raise HTTPException(401, "Current PIN is required to update your security questions")

    stored = [
        {"question": item.question.strip(), "answer_hash": hash_answer_for_storage(item.answer)}
        for item in body.items
    ]
    db_set_security_questions(address, stored)
    return {"success": True, "message": "Security questions saved."}


@app.get("/wallet/security-questions")
async def get_security_questions(address: str = Depends(get_current_address)):
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    stored = db_get_security_questions(wallet)
    if not stored:
        return {"has_security_questions": False, "questions": []}
    return {
        "has_security_questions": True,
        "questions": [item["question"] for item in stored],
    }


@app.post("/wallet/security-questions/verify")
async def verify_security_answers(
    body:    VerifySecurityAnswersRequest,
    address: str = Depends(get_current_address),
):
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    if _security_lock_active(wallet):
        raise HTTPException(429, "Too many failed attempts. Try again in a few minutes.")

    stored = db_get_security_questions(wallet)
    if not stored:
        raise HTTPException(400, "No security questions are set up for this wallet.")

    if len(body.answers) != len(stored):
        raise HTTPException(400, "Please answer all security questions.")

    stored_by_question = {item["question"]: item["answer_hash"] for item in stored}

    all_correct = True
    for submitted in body.answers:
        expected_hash = stored_by_question.get(submitted.question.strip())
        if not expected_hash or not verify_answer_hash(submitted.answer, expected_hash):
            all_correct = False
            break

    if not all_correct:
        db_record_security_failure(address, wallet.get("security_failed_count") or 0)
        raise HTTPException(401, "One or more answers are incorrect")

    db_reset_security_failures(address)
    grant = create_pin_reset_grant(address)
    return {
        "success":     True,
        "reset_grant": grant,
        "expires_in":  PIN_RESET_GRANT_TTL_SECONDS,
    }


@app.post("/wallet/reset-pin")
async def reset_pin(body: ResetPinRequest, address: str = Depends(get_current_address)):
    if not (body.pin.isdigit() and len(body.pin) == 6):
        raise HTTPException(400, "PIN must be exactly 6 digits")

    verify_pin_reset_grant(body.reset_grant, address)

    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    db_set_wallet_pin(address, hash_pin_for_storage(body.pin))
    return {"success": True, "message": "PIN reset successfully."}

# ─────────────────────────────────────────────────────────────────────────────
# Wallet address + export endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/wallet/addresses")
async def get_all_addresses(address: str = Depends(get_current_address)):
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    result: dict = {"evm": wallet["address"]}

    if wallet["wallet_type"] == "embedded" and wallet.get("encrypted_mnemonic"):
        mnemonic    = decrypt_mnemonic(wallet["encrypted_mnemonic"])
        sol_addr, _ = derive_solana_address(mnemonic)
        xlm_addr, _ = derive_stellar_address(mnemonic)
        result["solana"]  = sol_addr
        result["stellar"] = xlm_addr
    else:
        result["solana"]  = wallet.get("solana_address")
        result["stellar"] = wallet.get("stellar_address")

    return result


@app.post("/wallet/export-seed")
async def export_seed(address: str = Depends(get_current_address)):
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")
    if wallet.get("wallet_type") == "external":
        raise HTTPException(400, "External wallets have no stored seed phrase")
    if not wallet.get("encrypted_mnemonic"):
        raise HTTPException(404, "No seed phrase stored for this wallet")

    mnemonic    = decrypt_mnemonic(wallet["encrypted_mnemonic"])
    sol_addr, _ = derive_solana_address(mnemonic)
    xlm_addr, _ = derive_stellar_address(mnemonic)

    return {
        "mnemonic": mnemonic,
        "addresses": {"evm": address, "solana": sol_addr, "stellar": xlm_addr},
        "derivation_paths": {
            "evm":     "m/44'/60'/0'/0/0",
            "solana":  "m/44'/501'/0'/0'",
            "stellar": "m/44'/148'/0'",
        },
        "warning": "Store this phrase securely. Never share it.",
    }


@app.get("/wallet/all-addresses")
async def get_all_addresses_full(address: str = Depends(get_current_address)):
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")

    evm     = wallet["address"]
    solana  = wallet.get("solana_address")
    stellar = wallet.get("stellar_address")

    if wallet["wallet_type"] == "embedded" and wallet.get("encrypted_mnemonic"):
        mnemonic   = decrypt_mnemonic(wallet["encrypted_mnemonic"])
        solana, _  = derive_solana_address(mnemonic)
        stellar, _ = derive_stellar_address(mnemonic)

    return {
        "evm":          evm,
        "solana":       solana,
        "stellar":      stellar,
        "wallet_type":  wallet["wallet_type"],
        "has_mnemonic": bool(wallet.get("encrypted_mnemonic")),
    }


@app.post("/wallet/reset-pin-clear")
async def reset_pin_clear(body: ClearPinRequest, address: str = Depends(get_current_address)):
    verify_pin_reset_grant(body.reset_grant, address)
    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")
    supabase.table("wallets").update({
        "pin_hash":              None,
        "pin_failed_count":      0,
        "pin_locked_until":      None,
        "security_questions":    None,
        "security_failed_count": 0,
        "security_locked_until": None,
    }).eq("address", address.lower()).execute()
    return {"success": True, "message": "PIN cleared."}


@app.post("/wallet/export-privatekey")
async def export_privatekey(
    body:    ExportKeyRequest,
    address: str = Depends(get_current_address),
):
    consume_signing_grant(body.signing_grant, address)

    wallet = db_get_wallet(address)
    if not wallet:
        raise HTTPException(404, "Wallet not found")
    if wallet.get("wallet_type") == "external":
        raise HTTPException(400, "External wallets have no stored private key")
    if not wallet.get("encrypted_mnemonic"):
        raise HTTPException(404, "No mnemonic stored for this wallet")

    mnemonic = decrypt_mnemonic(wallet["encrypted_mnemonic"])
    EVM_CHAIN_IDS = {
        42220, 42161, 8453, 1135, 56, 677, 137, 10, 1,
        43114, 250, 100, 968, 1313161554, 1313161555,
    }

    if body.chain_id in EVM_CHAIN_IDS:
        Account.enable_unaudited_hdwallet_features()
        acct = Account.from_mnemonic(mnemonic, account_path="m/44'/60'/0'/0/0")
        return {
            "chain":           "evm",
            "chain_id":        body.chain_id,
            "address":         acct.address,
            "private_key":     acct.key.hex(),
            "derivation_path": "m/44'/60'/0'/0/0",
            "warning":         "Never share your private key.",
        }
    elif body.chain_id == 900:
        seed    = _mnemonic_to_seed(mnemonic)
        privkey = _derive_ed25519(seed, "m/44'/501'/0'/0'")
        kp      = SolanaKeypair.from_seed(privkey)
        return {
            "chain":            "solana",
            "chain_id":         body.chain_id,
            "address":          str(kp.pubkey()),
            "private_key":      list(kp.to_bytes_array()),
            "private_key_hex":  privkey.hex(),
            "derivation_path":  "m/44'/501'/0'/0'",
            "warning":          "Never share your private key.",
        }
    elif body.chain_id == 901:
        seed    = _mnemonic_to_seed(mnemonic)
        privkey = _derive_ed25519(seed, "m/44'/148'/0'")
        kp      = StellarKeypair.from_raw_ed25519_seed(privkey)
        return {
            "chain":           "stellar",
            "chain_id":        body.chain_id,
            "address":         kp.public_key,
            "private_key":     kp.secret,
            "derivation_path": "m/44'/148'/0'",
            "warning":         "Never share your private key.",
        }
    else:
        raise HTTPException(400, f"Unsupported chain_id: {body.chain_id}")


class UnlinkSocialRequest(BaseModel):
    provider: SocialProvider

@app.delete("/wallet/unlink-social")
async def unlink_social(
    body:    UnlinkSocialRequest,
    address: str = Depends(get_current_address),
):
    provider = body.provider

    linked = db_get_linked_socials(address)
    if provider not in linked:
        raise HTTPException(400, f"{provider} is not linked to this wallet")
    if len(linked) <= 1:
        raise HTTPException(400, "Cannot remove your only login method")

    supabase.table("linked_socials").delete().eq(
        "address", address.lower()
    ).eq("provider", provider).execute()

    updated = db_get_linked_socials(address)
    return {"success": True, "linked_socials": updated}

# ─────────────────────────────────────────────────────────────────────────────
# Phone OTP signup / login endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/auth/phone/send-otp")
async def phone_send_otp(body: SendOtpRequest):
    await send_otp(body.phone_number)
    return {"success": True, "message": "OTP sent. Please check your SMS."}


@app.post("/auth/phone/verify-otp", response_model=WalletResponse)
async def phone_verify_otp(body: VerifyOtpRequest):
    uid = await verify_otp(body.phone_number, body.code)
    wallet, legacy = get_or_create_wallet("phone", uid, handle=None)

    token  = create_token(wallet["address"])
    linked = db_get_linked_socials(wallet["address"])

    return WalletResponse(
        address            = wallet["address"],
        token              = token,
        linked_socials     = linked,
        evm_address        = wallet["address"],
        solana_address     = wallet.get("solana_address"),
        stellar_address    = wallet.get("stellar_address"),
        legacy_found       = legacy is not None,
        legacy_privy_id    = legacy["privy_id"]                    if legacy else None,
        legacy_evm_address = legacy.get("embedded_evm_address")    if legacy else None,
        legacy_sol_address = legacy.get("embedded_solana_address") if legacy else None,
        has_pin            = bool(wallet.get("pin_hash")),
        needs_seed_import  = (
            legacy is not None
            and bool(legacy.get("embedded_evm_address"))
            and not wallet.get("encrypted_mnemonic")
        ),
    )


@app.post("/wallet/link-phone")
async def link_phone(
    body:    LinkPhoneRequest,
    address: str = Depends(get_current_address),
):
    uid = await verify_otp(body.phone_number, body.code)
    link_social_to_wallet(address, "phone", uid, handle=None)
    linked = db_get_linked_socials(address)
    return {"success": True, "linked_socials": linked}

# ─────────────────────────────────────────────────────────────────────────────
# SCHEMA NOTES
# ─────────────────────────────────────────────────────────────────────────────
#
# linked_socials table — (provider, uid) unique key.
#   For SUPABASE_OAUTH_PROVIDERS (including passkey): uid = Supabase user UUID
#   For telegram/farcaster: uid = provider-native ID
#   For phone: uid = Supabase user UUID from /auth/v1/verify
#
# Columns required on `wallets`:
#   pin_hash               text
#   pin_failed_count       int  default 0
#   pin_locked_until       timestamptz
#   security_questions     text  (JSON)
#   security_failed_count  int  default 0
#   security_locked_until  timestamptz
#
# Table required for signing grant replay prevention:
#   create table if not exists used_signing_grants (
#     jti         text primary key,
#     expires_at  bigint not null
#   );
#
# Env:
#   ADMIN_KEY — required for /admin/backfill-profile-emails
#
# ─────────────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=10000, reload=True)