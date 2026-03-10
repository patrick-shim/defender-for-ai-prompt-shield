import os
import ast
import json
import requests
import sys
import time
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


def parse_bool_flag(name: str, default: bool = False) -> bool:
    prefix = f"--{name}="
    for arg in sys.argv[1:]:
        if arg.startswith(prefix):
            value = arg[len(prefix):].strip().lower()
            return value in {"1", "true", "yes", "on"}
    env_value = os.getenv(name.upper().replace("-", "_"))
    if env_value is None:
        return default
    return env_value.strip().lower() in {"1", "true", "yes", "on"}


def extract_content_filter_details(error: Exception) -> dict:
    text = str(error)
    marker = " - "
    payload = None
    if marker in text:
        payload_text = text.split(marker, 1)[1]
        try:
            payload = ast.literal_eval(payload_text)
        except (ValueError, SyntaxError):
            payload = None

    inner = (
        payload.get("error", {}).get("innererror", {})
        if isinstance(payload, dict) else {}
    )
    content_filter_result = inner.get("content_filter_result", {})
    summary = []

    for category, info in content_filter_result.items():
        if not isinstance(info, dict):
            continue
        if info.get("filtered"):
            severity = info.get("severity")
            detected = info.get("detected")
            if severity is not None:
                summary.append(f"{category}:{severity}")
            elif detected is not None:
                summary.append(f"{category}:detected")

    return {
        "raw_error": text,
        "content_filter_result": content_filter_result,
        "filter_summary": summary,
    }


def map_layer_label(layer: Optional[str]) -> str:
    layer_map = {
        "LAYER_1_APP_POLICY": "application_level_policy",
        "LAYER_1.5_AI_FOUNDRY_SAFETY": "azure_precheck",
        "LAYER_2_BEHAVIORAL": "application_level_policy",
        "LAYER_3_OPENAI": "azure_openai_filter",
    }
    return layer_map.get(layer, "unknown")


def build_compact_result(outcome: dict) -> dict:
    layer = outcome.get("blocked_by")
    reason = None

    if outcome.get("status") == "blocked":
        filter_summary = outcome.get("filter_summary") or []
        behavioral_pattern = outcome.get("behavioral_pattern")
        assistant_response = outcome.get("assistant_response")

        if filter_summary:
            reason = ", ".join(filter_summary)
        elif behavioral_pattern:
            reason = behavioral_pattern
        elif assistant_response:
            reason = assistant_response
    elif outcome.get("status") == "error":
        reason = outcome.get("error") or outcome.get("assistant_response")
    else:
        reason = "Allowed"

    return {
        "prompt_id": outcome.get("prompt_index"),
        "result": "blocked" if outcome.get("status") == "blocked" else "allowed",
        "layer": map_layer_label(layer),
        "reason": reason,
    }


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
    
    # Check if verbose logging is enabled
    verbose_logging = os.getenv("VERBOSE_LOGGING", "false").lower() == "true"
    origin_map = {
        "APP_INIT": "APP",
        "APP_CLEANUP": "APP",
        "APP_TERMINATION": "APP",
        "LAYER_1_APP_POLICY": "APP",
        "LAYER_1.5_AI_FOUNDRY_SAFETY": "AZURE",
        "LAYER_2_BEHAVIORAL": "APP",
        "LAYER_3_OPENAI": "MODEL",
    }
    origin = origin_map.get(layer, "APP")
    
    if verbose_logging:
        # Original detailed JSON output for debugging
        layer_str = f"[{layer}]" if layer else "[APP]"
        risk_color = "🔴" if ctx.risk_score >= 0.7 else "🟡" if ctx.risk_score >= 0.35 else "🟢"
        print(f"{layer_str} [{origin}] {risk_color} {event}: {json.dumps(record, ensure_ascii=False)}")
    else:
        # Clean, structured output format
        layer_str = f"[{layer}]" if layer else "[APP]"
        risk_color = "🔴" if ctx.risk_score >= 0.7 else "🟡" if ctx.risk_score >= 0.35 else "🟢"
        
        print(f"{layer_str} [{origin}] {risk_color} {event}")
        
        # Show key details in a readable format
        if details:
            if "error" in details:
                print(f"    ❌ Error: {details['error']}")
            elif "filter_summary" in details and details["filter_summary"]:
                print(f"    🚫 Filter reason: {', '.join(details['filter_summary'])}")
            elif "categories" in details:
                print(f"    🚫 Blocked categories: {', '.join(details['categories'])}")
                if "severity_scores" in details:
                    scores = details['severity_scores']
                    print(f"    📊 Severity scores: {', '.join([f'{k}:{v}' for k, v in scores.items() if v > 0])}")
            
            elif "attack_detected" in details:
                if details["attack_detected"]:
                    print(f"    🛡️  Jailbreak attack detected")
                else:
                    print(f"    ✅ No jailbreak detected")
            
            elif "len" in details:
                print(f"    📝 Length: {details['len']} chars")
            elif "pattern" in details:
                print(f"    🔍 Pattern: {details['pattern']}")
            elif "reason" in details:
                print(f"    📋 Reason: {details['reason']}")
            
            # Show risk score changes
            if "risk_score_after" in details:
                print(f"    ⚠️  Risk score: {details['risk_score_after']:.3f}")
    
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
    "high_severity_content":            0.30,   # High severity content detected
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
# AI Foundry Content Safety Integration (Layer 1.5)
# -----------------------------
def analyze_with_ai_foundry_filters(
    user_text: str,
    ctx: SecurityContext,
    client: AzureOpenAI,
    deployment: str
) -> Optional[dict]:
    """
    Use AI Foundry's built-in content filter signal as a pre-check.
    - If request succeeds, treat as safe.
    - If platform content filter blocks, treat as unsafe.
    """
    try:
        # Trigger platform-side filtering using a lightweight request.
        client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": "Safety pre-check."},
                {"role": "user", "content": user_text}
            ],
            temperature=1,
            max_completion_tokens=10
        )

        log_event("ai_foundry_content_analyzed", ctx, {
            "text_length": len(user_text)
        }, layer="LAYER_1.5_AI_FOUNDRY_SAFETY")

        return {"result": "ALLOWED", "safe": True}
        
    except BadRequestError as e:
        if "content_filter" in str(e):
            # Content was blocked by AI Foundry's built-in filters.
            filter_info = extract_content_filter_details(e)
            log_event("ai_foundry_content_blocked", ctx, {
                "filter_summary": filter_info["filter_summary"],
                "filter_reason": str(e),
                "text_length": len(user_text)
            }, layer="LAYER_1.5_AI_FOUNDRY_SAFETY")
            return {
                "result": "BLOCKED",
                "safe": False,
                "reason": str(e),
                "filter_summary": filter_info["filter_summary"],
                "filter_details": filter_info["content_filter_result"],
            }
        else:
            raise
    except Exception as e:
        log_event("ai_foundry_safety_error", ctx, {"error": str(e)}, layer="LAYER_1.5_AI_FOUNDRY_SAFETY")
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


def process_user_text(
    user_text: str,
    ctx: SecurityContext,
    client: AzureOpenAI,
    deployment: str,
    messages: list[dict],
    enforce_termination: bool = True,
    app_layer_enabled: bool = True
) -> dict:
    ctx.turn_count += 1

    result = {
        "prompt": user_text,
        "turn": ctx.turn_count,
        "status": "completed",
        "blocked_by": None,
        "assistant_response": None,
        "risk_score_before": round(ctx.risk_score, 3),
        "risk_score_after": round(ctx.risk_score, 3),
        "session_risk_after": ctx.session_risk,
    }

    if app_layer_enabled:
        blocked = apply_security_policy(user_text, ctx)
        if blocked:
            ctx.blocked_count += 1
            update_risk_score(ctx, "prompt_blocked_by_policy")
            log_event("prompt_blocked_by_policy", ctx, {
                "reason": blocked,
                "risk_score_after": ctx.risk_score,
            }, layer="LAYER_1_APP_POLICY")
            print(f"Assistant: {blocked}\n")
            result["status"] = "blocked"
            result["blocked_by"] = "LAYER_1_APP_POLICY"
            result["assistant_response"] = blocked
            result["risk_score_after"] = round(ctx.risk_score, 3)
            result["session_risk_after"] = ctx.session_risk
            result["terminated"] = check_terminate(ctx) if enforce_termination else False
            return result

    safety_analysis = analyze_with_ai_foundry_filters(user_text, ctx, client, deployment)
    if safety_analysis and not safety_analysis["safe"]:
        ctx.blocked_count += 1
        update_risk_score(ctx, "high_severity_content")
        if safety_analysis["result"] == "BLOCKED":
            log_event("ai_foundry_content_blocked", ctx, {
                "filter_summary": safety_analysis.get("filter_summary", []),
                "reason": safety_analysis.get("reason", "Content filter triggered"),
                "risk_score_after": ctx.risk_score,
            }, layer="LAYER_1.5_AI_FOUNDRY_SAFETY")
            message = "[Content blocked by AI Foundry safety filters]"
            print(f"Assistant: {message}\n")
            result["blocked_by"] = "LAYER_1.5_AI_FOUNDRY_SAFETY"
        
        else:
            log_event("ai_foundry_unsafe_content", ctx, {
                "analysis_result": safety_analysis["result"],
                "risk_score_after": ctx.risk_score,
            }, layer="LAYER_1.5_AI_FOUNDRY_SAFETY")
            message = "[Content flagged as potentially unsafe]"
            print(f"Assistant: {message}\n")
            result["blocked_by"] = "LAYER_1.5_AI_FOUNDRY_SAFETY"
        result["status"] = "blocked"
        result["assistant_response"] = message
        result["filter_summary"] = safety_analysis.get("filter_summary", [])
        result["filter_details"] = safety_analysis.get("filter_details", {})
        result["risk_score_after"] = round(ctx.risk_score, 3)
        result["session_risk_after"] = ctx.session_risk
        result["terminated"] = check_terminate(ctx) if enforce_termination else False
        return result

    if app_layer_enabled:
        pattern_block = detect_behavioral_pattern(ctx, messages)
        if pattern_block:
            ctx.blocked_count += 1
            log_event("behavioral_pattern_blocked", ctx, {
                "pattern": pattern_block,
                "risk_score_after": ctx.risk_score,
            }, layer="LAYER_2_BEHAVIORAL")
            print("Assistant: [Suspicious pattern detected. Session flagged.]\n")
            result["behavioral_pattern"] = pattern_block

    messages.append({"role": "user", "content": user_text})
    log_event("prompt_sent", ctx, {
        "len": len(user_text),
        "current_risk_score": ctx.risk_score,
        "session_risk": ctx.session_risk,
    }, layer="LAYER_3_OPENAI")

    try:
        resp = client.chat.completions.create(
            model=deployment,
            messages=messages,
            temperature=1,
        )
    except BadRequestError as e:
        if "content_filter" in str(e):
            filter_info = extract_content_filter_details(e)
            ctx.blocked_count += 1
            update_risk_score(ctx, "prompt_blocked_by_content_filter")
            log_event("prompt_blocked_by_content_filter", ctx, {
                "filter_summary": filter_info["filter_summary"],
                "risk_score_after": ctx.risk_score,
                "session_risk_after": ctx.session_risk,
            }, layer="LAYER_3_OPENAI")
            messages.pop()
            message = "[Blocked by content policy]"
            print(f"Assistant: {message}\n")
            result["status"] = "blocked"
            result["blocked_by"] = "LAYER_3_OPENAI"
            result["assistant_response"] = message
            result["filter_summary"] = filter_info["filter_summary"]
            result["filter_details"] = filter_info["content_filter_result"]
            result["risk_score_after"] = round(ctx.risk_score, 3)
            result["session_risk_after"] = ctx.session_risk
            result["terminated"] = check_terminate(ctx) if enforce_termination else False
            return result
        raise
    except (APITimeoutError, APIConnectionError) as e:
        log_event("openai_connection_error", ctx, {"error": str(e)}, layer="LAYER_3_OPENAI")
        messages.pop()
        message = "[Connection error — please try again]"
        print(f"Assistant: {message}\n")
        result["status"] = "error"
        result["blocked_by"] = "LAYER_3_OPENAI"
        result["assistant_response"] = message
        result["error"] = str(e)
        result["risk_score_after"] = round(ctx.risk_score, 3)
        result["session_risk_after"] = ctx.session_risk
        result["terminated"] = False
        return result

    answer = resp.choices[0].message.content
    messages.append({"role": "assistant", "content": answer})
    log_event("assistant_replied", ctx, {
        "len": len(answer),
        "turn": ctx.turn_count,
    }, layer="LAYER_3_OPENAI")
    print(f"Assistant: {answer}\n")

    result["assistant_response"] = answer
    result["risk_score_after"] = round(ctx.risk_score, 3)
    result["session_risk_after"] = ctx.session_risk
    result["terminated"] = False
    return result


def run_test_prompts(
    ctx: SecurityContext,
    client: AzureOpenAI,
    deployment: str,
    messages: list[dict],
    app_layer_enabled: bool
) -> None:
    prompts_path = os.getenv("TEST_PROMPTS_FILE", "test_prompts.json")
    results_path = os.getenv("TEST_RESULTS_FILE", "results.json")
    verbose_results_path = os.getenv("TEST_VERBOSE_RESULTS_FILE", "results_verbose.json")
    delay_seconds = int(os.getenv("TEST_PROMPT_DELAY_SECONDS", "5"))

    with open(prompts_path, "r", encoding="utf-8") as f:
        prompts = json.load(f)

    results = []
    verbose_results = []
    total = len(prompts)
    print(f"Running {total} test prompts from {prompts_path}.\n")

    for index, item in enumerate(prompts, start=1):
        prompt_index = item.get("prompt_index", str(index - 1))
        prompt_text = item.get("prompt") or item.get("prompt_texts", "")
        expected_result = item.get("expected_result")

        print(f"[{index}/{total}] Prompt {prompt_index}")
        print(f"You: {prompt_text}")

        outcome = process_user_text(
            prompt_text,
            ctx,
            client,
            deployment,
            messages,
            enforce_termination=False,
            app_layer_enabled=app_layer_enabled,
        )
        outcome["prompt_index"] = prompt_index
        outcome["expected_result"] = expected_result
        outcome["timestamp"] = utc_now()
        verbose_results.append(outcome)
        results.append(build_compact_result(outcome))

        if index < total:
            time.sleep(delay_seconds)

    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    with open(verbose_results_path, "w", encoding="utf-8") as f:
        json.dump(verbose_results, f, ensure_ascii=False, indent=2)

    print(f"Saved {len(results)} compact results to {results_path}.")
    print(f"Saved {len(verbose_results)} verbose results to {verbose_results_path}.\n")


# -----------------------------
# Main loop
# -----------------------------
def main() -> None:
    deployment = require_env("AZURE_OPENAI_DEPLOYMENT")
    endpoint = require_env("AZURE_OPENAI_ENDPOINT")
    api_version = os.getenv("OPENAI_API_VERSION", "2025-04-01-preview")
    app_layer_enabled = parse_bool_flag("app-layer", default=True)

    # Single shared credential instance — reused across OpenAI and Content Safety
    credential = DefaultAzureCredential()

    # In production: populate SecurityContext from Entra ID JWT token claims
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
        "app_layer_enabled": app_layer_enabled,
    }, layer="APP_INIT")

    if "--batch" in sys.argv or os.getenv("RUN_TEST_PROMPTS", "false").lower() == "true":
        run_test_prompts(ctx, client, deployment, messages, app_layer_enabled)
        log_event("session_ended", ctx, {
            "final_risk_score": ctx.risk_score,
            "total_turns": ctx.turn_count,
            "total_blocks": ctx.blocked_count,
            "jailbreak_attempts": ctx.jailbreak_attempts,
        }, layer="APP_CLEANUP")
        return

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

        outcome = process_user_text(
            user_text,
            ctx,
            client,
            deployment,
            messages,
            app_layer_enabled=app_layer_enabled,
        )
        if outcome.get("terminated"):
            break


if __name__ == "__main__":
    main()