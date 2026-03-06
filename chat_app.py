import os
import json
import requests
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional

from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential, get_bearer_token_provider
from openai import AzureOpenAI, BadRequestError, APITimeoutError, APIConnectionError

load_dotenv(override=True)

print("CWD:", os.getcwd())
print("DEPLOYMENT:", os.getenv("AZURE_OPENAI_DEPLOYMENT"))
print("ENDPOINT:", os.getenv("AZURE_OPENAI_ENDPOINT"))
print("CONTENT_SAFETY_ENDPOINT:", os.getenv("AZURE_CONTENT_SAFETY_ENDPOINT"))
print("API_KEY set:", bool(os.getenv("AZURE_OPENAI_API_KEY")))


# -----------------------------
# SecurityContext (app-side)
# -----------------------------
@dataclass
class SecurityContext:
    tenant_id: str
    user_id: str
    roles: list[str]
    auth_strength: str          # e.g., "MFA", "PasswordOnly"
    session_risk: str           # e.g., "low", "medium", "high" — updated dynamically
    data_classification: str    # e.g., "Public", "Internal", "Confidential"
    correlation_id: str

    # Dynamic behavior tracking — updated each turn
    turn_count: int = 0
    blocked_count: int = 0          # total blocks this session
    jailbreak_attempts: int = 0     # explicit jailbreak detections
    risk_score: float = 0.0         # 0.0 = clean, 1.0 = max risk
    escalation_history: list = field(default_factory=list)


# -----------------------------
# Helpers
# -----------------------------
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(event: str, ctx: SecurityContext, details: dict, layer: str = None) -> None:
    """
    Structured audit logging with layer detection.
    NOTE: Never log secrets/tokens or full prompt content in production.
    """
    record = {
        "time": utc_now(),
        "event": event,
        "layer": layer,  # NEW: Which security layer detected this
        "correlation_id": ctx.correlation_id,
        "tenant_id": ctx.tenant_id,
        "user_id": ctx.user_id,
        "roles": ctx.roles,
        "auth_strength": ctx.auth_strength,
        "session_risk": ctx.session_risk,
        "data_classification": ctx.data_classification,
        "risk_score": round(ctx.risk_score, 3),
        "details": details,
    }
    
    # Enhanced readable output for console
    layer_str = f"[{layer}]" if layer else "[APP]"
    risk_color = "🔴" if ctx.risk_score >= 0.7 else "🟡" if ctx.risk_score >= 0.35 else "🟢"
    
    print(f"{layer_str} {risk_color} {event}: {json.dumps(record, ensure_ascii=False)}")
    return record


# -----------------------------
# Environment validation
# -----------------------------
def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


# -----------------------------
# Azure OpenAI client (Entra ID auth)
# -----------------------------
def make_client(credential: DefaultAzureCredential) -> AzureOpenAI:
    """
    Authenticates via DefaultAzureCredential (Entra ID / Azure CLI login).
    Key-based auth is disabled on this resource so we use a bearer token provider.
    Run `az login` before starting if token is expired.
    """
    endpoint = require_env("AZURE_OPENAI_ENDPOINT")
    api_version = os.getenv("OPENAI_API_VERSION", "2025-04-01-preview")

    token_provider = get_bearer_token_provider(
        credential,
        "https://cognitiveservices.azure.com/.default"
    )

    return AzureOpenAI(
        azure_endpoint=endpoint,
        azure_ad_token_provider=token_provider,
        api_version=api_version,
        timeout=60.0,       # increase from default 10s
        max_retries=3,      # auto-retry on transient failures
    )


# -----------------------------
# Dynamic risk scoring
# -----------------------------
RISK_WEIGHTS = {
    "prompt_blocked_by_policy":         0.10,
    "prompt_blocked_by_content_filter": 0.25,   # Azure OpenAI confirmed bad signal
    "prompt_shield_blocked":            0.40,   # Prompt Shields confirmed jailbreak
    "credential_probe":                 0.30,
    "behavioral_pattern_detected":      0.20,
}

def update_risk_score(ctx: SecurityContext, event: str) -> None:
    """Recompute risk score and session_risk label after each adverse event."""
    ctx.risk_score = min(1.0, ctx.risk_score + RISK_WEIGHTS.get(event, 0.0))
    ctx.escalation_history.append({"turn": ctx.turn_count, "event": event})

    if ctx.risk_score >= 0.7:
        ctx.session_risk = "high"
    elif ctx.risk_score >= 0.35:
        ctx.session_risk = "medium"
    else:
        ctx.session_risk = "low"


# -----------------------------
# Prompt Shields via REST API (Layer 1.5) — logs to MDC
# SDK v1.0.0 does not support ShieldPromptOptions so we call REST directly.
# -----------------------------
def shield_prompt(
    user_text: str,
    ctx: SecurityContext,
    credential: DefaultAzureCredential
) -> Optional[str]:
    """
    Call Azure AI Content Safety Prompt Shields REST API directly.
    Detects jailbreak and prompt injection attempts.
    Signals from this API are logged to Microsoft Defender for Cloud.
    Returns a refusal string if an attack is detected, otherwise None.
    """
    cs_endpoint = require_env("AZURE_CONTENT_SAFETY_ENDPOINT").rstrip("/")
    url = f"{cs_endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01"

    try:
        token = credential.get_token("https://cognitiveservices.azure.com/.default").token

        resp = requests.post(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={
                "userPrompt": user_text,
                "documents": []
            },
            timeout=10,
        )
        resp.raise_for_status()
        result = resp.json()

        attack_detected = result.get("userPromptAnalysis", {}).get("attackDetected", False)

        log_event("prompt_shield_scanned", ctx, {
            "attack_detected": attack_detected,
            "raw": result,
        }, layer="LAYER_1.5_PROMPT_SHIELDS")

        if attack_detected:
            ctx.jailbreak_attempts += 1
            update_risk_score(ctx, "prompt_shield_blocked")
            log_event("prompt_shield_blocked", ctx, {
                "risk_score_after": ctx.risk_score,
                "session_risk_after": ctx.session_risk,
            }, layer="LAYER_1.5_PROMPT_SHIELDS")
            return "Request blocked: prompt injection or jailbreak attempt detected."

    except Exception as e:
        # Don't crash the app if Content Safety is unavailable — log and continue
        log_event("prompt_shield_error", ctx, {"error": str(e)}, layer="LAYER_1.5_PROMPT_SHIELDS")

    return None


# -----------------------------
# Behavioral pattern detection (cross-turn)
# -----------------------------
SUSPICIOUS_PATTERNS = [
    # Gradual jailbreak escalation
    ["ignore", "pretend", "jailbreak"],
    # Credential probing sequence
    ["api key", "token", "secret", "password"],
    # Prompt injection setup
    ["summarize this", "ignore previous", "new instructions"],
]

def detect_behavioral_pattern(
    ctx: SecurityContext,
    history: list[dict]
) -> Optional[str]:
    """
    Scan last 5 user messages for multi-turn suspicious patterns.
    Returns a reason string if detected, otherwise None.
    """
    recent = [
        m["content"].lower()
        for m in history[-10:]
        if m["role"] == "user"
    ][-5:]

    for pattern in SUSPICIOUS_PATTERNS:
        matches = sum(
            1 for msg in recent
            if any(keyword in msg for keyword in pattern)
        )
        if matches >= 2:
            update_risk_score(ctx, "behavioral_pattern_detected")
            return f"Suspicious multi-turn pattern detected: {pattern}"

    return None


# -----------------------------
# Dynamic system prompt based on SecurityContext
# -----------------------------
def build_system_prompt(ctx: SecurityContext) -> str:
    base = "You are a helpful assistant. Be concise and security-aware."

    if ctx.data_classification == "Confidential":
        base += " Never summarize, copy, or repeat document contents verbatim."

    if "Guest" in ctx.roles:
        base += " You may only answer general questions. Refuse internal data requests."

    if ctx.session_risk == "high":
        base += (
            " Be extra cautious. Refuse any requests involving credentials, "
            "code execution, system access, or policy overrides."
        )

    return base


# -----------------------------
# App-side security policy (Layer 1)
# -----------------------------
def apply_security_policy(user_text: str, ctx: SecurityContext) -> Optional[str]:
    """
    Fast app-side gate using SecurityContext.
    Returns a refusal string if blocked, otherwise None.
    This runs BEFORE the Azure OpenAI call.
    """
    low = user_text.lower()

    # High-risk session: block credential/secret probing
    if ctx.session_risk == "high" and any(
        k in low for k in ["password", "secret", "token", "apikey", "api key"]
    ):
        update_risk_score(ctx, "credential_probe")
        return "I can't help with credential or secret extraction requests."

    # Confidential data: block external sharing attempts
    if ctx.data_classification == "Confidential" and "send to" in low and "@" in low:
        return "I can't assist with sharing confidential information externally."

    # Non-MFA users blocked from sensitive operations
    sensitive_ops = ["delete", "drop", "truncate", "disable", "revoke", "purge"]
    if any(op in low for op in sensitive_ops) and ctx.auth_strength != "MFA":
        return "Destructive operations require MFA authentication. Please re-authenticate."

    return None


# -----------------------------
# Session termination check (shared helper)
# -----------------------------
def check_terminate(ctx: SecurityContext) -> bool:
    """Returns True if session should be terminated due to high risk."""
    if ctx.risk_score >= 0.7:
        log_event("session_terminated_high_risk", ctx, {
            "final_risk_score": ctx.risk_score,
            "total_blocks": ctx.blocked_count,
            "jailbreak_attempts": ctx.jailbreak_attempts,
        }, layer="APP_TERMINATION")
        print("Session terminated due to repeated policy violations.\n")
        return True
    return False


# -----------------------------
# Main loop
# -----------------------------
def main() -> None:
    deployment = require_env("AZURE_OPENAI_DEPLOYMENT")
    endpoint = require_env("AZURE_OPENAI_ENDPOINT")
    api_version = os.getenv("OPENAI_API_VERSION", "2025-04-01-preview")

    # Single shared credential instance — reused across OpenAI and Content Safety
    credential = DefaultAzureCredential()

    # In production: populate SecurityContext from Entra ID JWT token claims
    # ctx = build_context_from_token(request.headers["Authorization"])
    ctx = SecurityContext(
        tenant_id=os.getenv("TENANT_ID", "security-tenant-demo"),
        user_id=os.getenv("USER_ID", "demo@example.com"),
        roles=os.getenv("USER_ROLES", "AI-Sec,GBB").split(","),
        auth_strength=os.getenv("AUTH_STRENGTH", "MFA"),
        session_risk="low",
        data_classification=os.getenv("DATA_CLASSIFICATION", "Internal"),
        correlation_id=str(uuid4()),
    )

    client = make_client(credential)

    messages = [
        {"role": "system", "content": build_system_prompt(ctx)}
    ]

    log_event("session_started", ctx, {
        "deployment": deployment,
        "endpoint": endpoint,
        "api_version": api_version,
        "initial_risk_score": ctx.risk_score,
    }, layer="APP_INIT")

    print("Type your message. Type /quit to exit.\n")

    while True:
        user_text = input("You: ").strip()
        if not user_text:
            continue

        if user_text.lower() in ("/quit", "quit", "exit"):
            log_event("session_ended", ctx, {
                "final_risk_score": ctx.risk_score,
                "total_turns": ctx.turn_count,
                "total_blocks": ctx.blocked_count,
                "jailbreak_attempts": ctx.jailbreak_attempts,
            }, layer="APP_CLEANUP")
            break

        ctx.turn_count += 1

        # --- Layer 1: App-side policy gate (SecurityContext-aware) ---
        blocked = apply_security_policy(user_text, ctx)
        if blocked:
            ctx.blocked_count += 1
            update_risk_score(ctx, "prompt_blocked_by_policy")
            log_event("prompt_blocked_by_policy", ctx, {
                "reason": blocked,
                "risk_score_after": ctx.risk_score,
            }, layer="LAYER_1_APP_POLICY")
            print(f"Assistant: {blocked}\n")
            if check_terminate(ctx):
                break
            continue

        # --- Layer 1.5: Prompt Shields REST API (logs jailbreaks to MDC) ---
        shield_block = shield_prompt(user_text, ctx, credential)
        if shield_block:
            ctx.blocked_count += 1
            print(f"Assistant: {shield_block}\n")
            if check_terminate(ctx):
                break
            continue

        # --- Layer 2: Behavioral pattern detection (cross-turn) ---
        pattern_block = detect_behavioral_pattern(ctx, messages)
        if pattern_block:
            ctx.blocked_count += 1
            log_event("behavioral_pattern_blocked", ctx, {
                "pattern": pattern_block,
                "risk_score_after": ctx.risk_score,
            }, layer="LAYER_2_BEHAVIORAL")
            print("Assistant: [Suspicious pattern detected. Session flagged.]\n")

        messages.append({"role": "user", "content": user_text})
        log_event("prompt_sent", ctx, {
            "len": len(user_text),
            "current_risk_score": ctx.risk_score,
            "session_risk": ctx.session_risk,
        }, layer="LAYER_3_OPENAI")

        # --- Layer 3: Azure OpenAI + Content Filter ---
        try:
            resp = client.chat.completions.create(
                model=deployment,
                messages=messages,
                temperature=1,
            )

        except BadRequestError as e:
            if "content_filter" in str(e):
                ctx.blocked_count += 1
                update_risk_score(ctx, "prompt_blocked_by_content_filter")
                log_event("prompt_blocked_by_content_filter", ctx, {
                    "risk_score_after": ctx.risk_score,
                    "session_risk_after": ctx.session_risk,
                }, layer="LAYER_3_OPENAI")
                messages.pop()  # remove blocked message from history
                print("Assistant: [Blocked by content policy]\n")
                if check_terminate(ctx):
                    break
            else:
                raise
            continue

        except (APITimeoutError, APIConnectionError) as e:
            log_event("openai_connection_error", ctx, {"error": str(e)}, layer="LAYER_3_OPENAI")
            messages.pop()
            print("Assistant: [Connection error — please try again]\n")
            continue

        answer = resp.choices[0].message.content
        messages.append({"role": "assistant", "content": answer})
        log_event("assistant_replied", ctx, {
            "len": len(answer),
            "turn": ctx.turn_count,
        }, layer="LAYER_3_OPENAI")

        print(f"Assistant: {answer}\n")


if __name__ == "__main__":
    main()