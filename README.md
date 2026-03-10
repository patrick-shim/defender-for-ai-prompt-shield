# Defender for AI Prompt Shield Demo

This project demonstrates how to exercise **Azure AI Foundry / Azure OpenAI safety controls** and inspect the resulting behavior in both the console and `results.json`.

The current code is intentionally optimized for **demo clarity**:

- Azure-side safety pre-checks
- Azure OpenAI content filter enforcement
- model-level refusals
- optional app-side controls that can be turned on or off
- batch prompt execution for validation runs

## What the app does

`chat_app.py` is a console app that sends prompts through a layered pipeline and logs which layer handled or blocked the request.

It supports two main demo modes:

- **Interactive mode** for ad hoc testing
- **Batch mode** for replaying `test_prompts.json` and writing structured output to `results.json`

## Current architecture

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

## Source tags in logs

Console logs include a source marker so you can see where the event originated:

- `[APP]`
- `[AZURE]`
- `[MODEL]`

Example:

```text
[LAYER_1.5_AI_FOUNDRY_SAFETY] [AZURE] 🟢 ai_foundry_content_analyzed
[LAYER_3_OPENAI] [MODEL] 🟢 prompt_sent
[LAYER_3_OPENAI] [MODEL] 🟢 assistant_replied
```

## Risk scoring

The app maintains an internal `risk_score` in `SecurityContext`.

This score is **app-evaluated**, not returned by Azure.

Current weights in `chat_app.py`:

| Event | Score |
|---|---:|
| `prompt_blocked_by_policy` | `0.10` |
| `behavioral_pattern_detected` | `0.20` |
| `prompt_blocked_by_content_filter` | `0.25` |
| `high_severity_content` | `0.30` |
| `credential_probe` | `0.30` |
| `prompt_shield_blocked` | `0.40` |

Current session labels:

| Risk score | Session risk |
|---|---|
| `0.00 - 0.34` | `low` |
| `0.35 - 0.69` | `medium` |
| `0.70+` | `high` |

In interactive mode, a high-risk session can terminate early.

In batch mode, termination is intentionally not enforced so all prompts can be tested.

## App-layer toggle

The app supports a runtime toggle to simplify demos.

### `--app-layer=true`
Full behavior:

- Layer 1 enabled
- Layer 2 enabled
- Azure pre-check enabled
- model/content filter enabled

### `--app-layer=false`
Azure/model-focused demo mode:

- Layer 1 disabled
- Layer 2 disabled
- Layer 1.5 Azure safety enabled
- Layer 3 model/content filter enabled

This is useful when you want to demonstrate **Defender for AI / Azure AI Foundry capabilities** without app-side methodology affecting the narrative.

You can also use environment variable fallback:

```dotenv
APP_LAYER=true
```

## Batch testing

Batch mode reads prompts from `test_prompts.json`, submits them one at a time, waits between prompts, and writes results to `results.json`.

### Run batch mode

```powershell
python .\chat_app.py --batch
```

To run without app-side layers:

```powershell
python .\chat_app.py --batch --app-layer=false
```

### Batch mode configuration

Optional environment variables:

```dotenv
RUN_TEST_PROMPTS=false
TEST_PROMPTS_FILE=test_prompts.json
TEST_RESULTS_FILE=results.json
TEST_PROMPT_DELAY_SECONDS=5
```

## Results file

Batch execution writes `results.json`.

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

## Environment configuration

Create a local `.env` file.

Example:

```dotenv
AZURE_OPENAI_ENDPOINT=https://<your-resource>.cognitiveservices.azure.com
OPENAI_API_VERSION=2024-12-01-preview
AZURE_OPENAI_DEPLOYMENT=<your-deployment-name>

TENANT_ID=test-tenant
USER_ID=demo-user
USER_ROLES=AI-Sec,GBB
AUTH_STRENGTH=MFA
DATA_CLASSIFICATION=Internal

VERBOSE_LOGGING=false
APP_LAYER=true
TEST_PROMPTS_FILE=test_prompts.json
TEST_RESULTS_FILE=results.json
TEST_PROMPT_DELAY_SECONDS=5
```

### Notes

- `AZURE_OPENAI_API_KEY` is printed only as a debug presence check and is not required when using Entra ID auth.
- `AZURE_CONTENT_SAFETY_ENDPOINT` is no longer part of the active execution path, even if still present in local environment files.

## Running the app

### Interactive mode

```powershell
python .\chat_app.py
```

### Interactive mode without app-side layers

```powershell
python .\chat_app.py --app-layer=false
```

### Batch mode without app-side layers

```powershell
python .\chat_app.py --batch --app-layer=false
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

## Defender / portal review

After running your test prompts, review:

- Microsoft Defender portal: `https://security.microsoft.com`
- Azure portal: `https://portal.azure.com`

Useful correlation inputs:

- batch run timestamp
- Azure resource / deployment used
- prompt timing from `results.json`
- `correlation_id` from console logs

Keep in mind:

- `risk_score` is app-side only
- `blocked_by` is app-side only
- Azure/Defender will have their own native signal representation

## File overview

```text
.
├── chat_app.py
├── test_prompts.json
├── results.json
├── .env.sample
└── README.md
```

## Known limitations

- The app still prints `CONTENT_SAFETY_ENDPOINT` at startup if present in the environment, even though the current safety path uses Azure AI Foundry / Azure OpenAI rather than the separate Content Safety REST flow.
- Some prompts may be blocked at Layer 1.5 in one run and Layer 3 in another depending on request shape and context.
- `SecurityContext` values are demo-oriented and should be replaced with real identity context in production.
- `risk_score` is a local app heuristic, not a Microsoft-native risk metric.

## References

- [Azure OpenAI Python SDK](https://github.com/openai/openai-python/blob/main/examples/azure.py)
- [Azure AI Foundry / Azure OpenAI content filtering](https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/content-filter)
- [DefaultAzureCredential](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential)
- [Microsoft Defender portal](https://security.microsoft.com)

This repository is a demo/reference project. Adapt authentication, logging, and policy behavior before using it in production.