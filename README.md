# Defender for AI Prompt Shield Demo

This project demonstrates how to exercise **Azure AI Foundry / Azure OpenAI safety controls** (including Prompt Shields) and compare behavior across:

- Azure OpenAI with Prompt Shields **Annotate + Block**
- Azure OpenAI with Prompt Shields **Annotate only**
- Anthropic Claude (in-band refusals)

It focuses on capturing each provider's most **native** response or error payloads and then deriving a consistent decision label for analysis.

The current code is intentionally optimized for **demo clarity**:

- Azure-side safety pre-checks
- Azure OpenAI content filter enforcement
- model-level refusals
- optional app-side controls that can be turned on or off
- batch prompt execution for validation runs

## Quick start

1) Create a `.env` file locally by copying `.env.sample`.

2) Run one mode at a time (batch example):

```powershell
python .\single_chat_app.py --azure-default --batch
python .\single_chat_app.py --azure-permissive --batch
python .\single_chat_app.py --claude --batch
```

3) Summarize and compare results:

```powershell
python .\analyze_results.py
```

## Main entrypoints

### `single_chat_app.py`

Runs a single provider/policy mode and writes a provider-specific result file:

- `--azure-default` -> `result_azure_default.json` (Prompt Shields annotate+block deployment)
- `--azure-permissive` -> `result_azure_permissive.json` (Prompt Shields annotate-only deployment)
- `--claude` -> `result_claude.json`

Modes:

- Interactive: omit `--batch`
- Batch: include `--batch` (reads `test_prompts.json` by default)

Each row includes:

- `status` (`ok` / `blocked` / `error`)
- `blocked` (transport/policy hard block)
- `refusal` (heuristic based on assistant text when available)
- `derived` (`allow` / `soft_refuse` / `hard_block` / `error`)
- `native` (best-effort native response/error payload)

### `analyze_results.py`

Loads `result_azure_default.json`, `result_azure_permissive.json`, and `result_claude.json`, aligns by `prompt_index`, and prints:

- Counts by `derived`
- Pairwise agreement matrices
- Mismatch lists with short text snippets

No output files are written.

## Optional: multilayer demo app

`chat_app_multilayer_example.py` is a legacy/demo console app that implements an application-layer pipeline (risk scoring, multi-layer gating) and writes to:

- `results.json`
- `results_verbose.json`

```text
User Prompt
   |
   +--> LAYER 1   [APP]    App-side policy gate (optional)
   |
   +--> LAYER 1.5 [AZURE]  Azure AI Foundry safety pre-check
   |
   +--> LAYER 2   [APP]    Behavioral pattern detection (optional)
   |
   +--> LAYER 3   [MODEL]  Azure OpenAI model call + content filter
```

### Layer summary

#### `LAYER_1_APP_POLICY` `[APP]`
App-controlled checks such as:

- credential probing in high-risk sessions
- destructive operation gating for non-MFA users
- confidential data sharing checks

This layer is **optional** and can be disabled with `--app-layer=false`.

#### `LAYER_1.5_AI_FOUNDRY_SAFETY` `[AZURE]`
A lightweight Azure AI Foundry / Azure OpenAI pre-check.

Behavior:

- if Azure accepts the request, it is treated as `ai_foundry_content_analyzed`
- if Azure blocks the request with `content_filter`, it is treated as `ai_foundry_content_blocked`

This is where Azure-side filter details such as:

- `jailbreak:detected`
- `hate:high`
- `violence:high`

can be surfaced.

#### `LAYER_2_BEHAVIORAL` `[APP]`
Cross-turn pattern detection based on recent user history.

Examples:

- gradual jailbreak escalation
- repeated credential probing patterns
- instruction-manipulation sequences

This layer is also **optional** and is disabled when `--app-layer=false`.

#### `LAYER_3_OPENAI` `[MODEL]`
The actual Azure OpenAI model call.

Possible outcomes:

- `prompt_sent`
- `assistant_replied`
- `prompt_blocked_by_content_filter`
- `openai_connection_error`

This is also where the model may safely refuse a prompt even if Azure did not hard-block it earlier.

## Environment configuration

Create a local `.env` file (not committed). Use `.env.sample` as the template.

Key variables used by `single_chat_app.py`:

```dotenv
AZURE_OPENAI_ENDPOINT=https://<your-resource>.cognitiveservices.azure.com/
OPENAI_API_VERSION=2025-01-01-preview

AZURE_OPENAI_DEPLOYMENT_DEFAULT=gpt-5-default
AZURE_OPENAI_DEPLOYMENT_PERMISSIVE=gpt-5-permissive

AZURE_MAX_TOKENS=512
AZURE_TEMPERATURE=1

ANTHROPIC_API_KEY=<your-anthropic-api-key>
ANTHROPIC_MODEL=claude-sonnet-4-6
ANTHROPIC_MAX_TOKENS=1024
```

## Output files

`single_chat_app.py` writes:

- `result_azure_default.json`
- `result_azure_permissive.json`
- `result_claude.json`

`chat_app_multilayer_example.py` writes:

- `results.json`
- `results_verbose.json`

## Results file

Batch execution for the multilayer example writes `results.json`.

Each result includes fields such as:

- `prompt_index`
- `prompt`
- `expected_result`
- `status`
- `blocked_by`
- `assistant_response`
- `risk_score_before`
- `risk_score_after`
- `session_risk_after`
- `filter_summary`
- `filter_details`
- `timestamp`

### Example blocked result

```json
{
  "status": "blocked",
  "blocked_by": "LAYER_3_OPENAI",
  "assistant_response": "[Blocked by content policy]",
  "filter_summary": [
    "hate:high",
    "jailbreak:detected",
    "violence:high"
  ]
}
```

### Meaning of `blocked_by`

- `LAYER_1_APP_POLICY` = blocked by app rule
- `LAYER_1.5_AI_FOUNDRY_SAFETY` = blocked by Azure pre-check
- `LAYER_3_OPENAI` = blocked by Azure OpenAI content filter during main model call
- `null` with `status = completed` = request was answered successfully or safely refused by the model

## Requirements

- Python 3.10+
- Azure OpenAI / Azure AI Foundry deployment
- `az login`
- RBAC allowing `DefaultAzureCredential` to call the Azure OpenAI resource

## Python packages

Install the currently used dependencies:

```bash
pip install openai azure-identity python-dotenv requests
```

## Running

### `single_chat_app.py` interactive

```powershell
python .\single_chat_app.py --azure-permissive
```

### `single_chat_app.py` batch

```powershell
python .\single_chat_app.py --azure-default --batch
```

### Analyze

```powershell
python .\analyze_results.py
```

## Current behavior notes

### Azure pre-check versus model refusal

Not every suspicious prompt is hard-blocked by Azure.

Possible outcomes:

- Azure blocks the prompt before the model call
- Azure allows the prompt, but the model refuses safely
- Azure allows the prompt and the model answers normally

This is why some prompts show:

- `blocked_by = LAYER_1.5_AI_FOUNDRY_SAFETY`
- `blocked_by = LAYER_3_OPENAI`
- or `status = completed` with a safe refusal response

### Azure filter reasons

When Azure returns a content filter block, the app extracts and records the returned filter categories. Common examples:

- `jailbreak:detected`
- `hate:high`
- `violence:high`
- `sexual:medium`

These values come from the Azure error payload.

## File overview

```text
.
├── single_chat_app.py
├── analyze_results.py
├── test_prompts.json
├── result_azure_default.json
├── result_azure_permissive.json
├── result_claude.json
├── .env.sample
├── chat_app_multilayer_example.py
├── results.json
├── results_verbose.json
└── README.md
```

## Known limitations

- The app still prints `CONTENT_SAFETY_ENDPOINT` at startup if present in the environment, even though the current safety path uses Azure AI Foundry / Azure OpenAI rather than the separate Content Safety REST flow.
- Some prompts may be blocked at Layer 1.5 in one run and Layer 3 in another depending on request shape and context.
- `risk_score` is a local app heuristic, not a Microsoft-native risk metric.

## References

- [Azure OpenAI Python SDK](https://github.com/openai/openai-python/blob/main/examples/azure.py)
- [Azure AI Foundry / Azure OpenAI content filtering](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/content-filter)
- [DefaultAzureCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential)
- [Microsoft Defender portal](https://security.microsoft.com)

This repository is a demo/reference project. Adapt authentication, logging, and policy behavior before using it in production.