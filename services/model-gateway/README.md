# Model gateway

This service is the only application component allowed to call an external model API. Select `openai` or `anthropic` with `MODEL_PROVIDER`. Both adapters reuse the same strict JSON Schema contracts for Lab generation, independent review, and free-text rubric grading. The gateway reconstructs the trusted LabSpec from operator-owned catalogs instead of accepting a model-authored build specification.

The OpenAI adapter uses the Responses API with strict JSON Schema output, response storage disabled, and no tools. The Anthropic adapter uses the official `@anthropic-ai/sdk` Messages API client with `output_config.format.type=json_schema`, no tools or metadata, and accepts only one completed assistant text block. Provider refusals, truncated responses, malformed JSON, oversized bodies, and contract violations fail closed.

## Privacy boundary

Do not send a user ID, email address, OIDC subject, organization ID, or any other direct identifier to the provider. The gateway intentionally omits OpenAI `safety_identifier` and Anthropic `metadata`. A future abuse-correlation feature may add an opaque HMAC-derived identifier only after its end-to-end trust boundary and key rotation are implemented.

## Required secrets

- `MODEL_GATEWAY_INTERNAL_TOKEN`: shared only with the AI service.
- OpenAI: `MODEL_PROVIDER=openai`, `OPENAI_API_KEY`, and `OPENAI_MODEL`.
- Claude: `MODEL_PROVIDER=anthropic`, `ANTHROPIC_API_KEY`, and `ANTHROPIC_MODEL`.

The selected key is neither logged nor included in model input. Official origins are fixed to `https://api.openai.com/v1` and `https://api.anthropic.com/v1`; redirects and custom origins are rejected. Claude uses `ANTHROPIC_VERSION=2023-06-01` by default. Provider-neutral timeout variables are `MODEL_GATEWAY_GENERATION_TIMEOUT_MS`, `MODEL_GATEWAY_REVIEW_TIMEOUT_MS`, and `MODEL_GATEWAY_RUBRIC_TIMEOUT_MS`; the legacy provider-prefixed timeout names remain accepted. `MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS` defaults to `1` and accepts only `1` or `2`.

## Local raw-response diagnosis

Raw response capture is disabled by default and must remain disabled in production. For one local generation request only, set `MODEL_GATEWAY_DEBUG_RAW_RESPONSE_CAPTURE=local-explicit`. Any other defined value is rejected at startup. A successful Anthropic generation HTTP response is written byte-for-byte, before parsing, to the fixed container path `/tmp/zerotop-generation-provider-response.json`. The file is created with exclusive-create semantics and mode `0600`; an existing file or any write failure fails the request instead of overwriting data. The capture contains only the response body—never headers, the API key, or the request body—but it can contain generated training content and hidden answers.

Keep `MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS=1` while capturing. Copy the file to a secure location outside a synchronized repository if analysis is required, then remove the container file and unset the capture variable. Never commit or share the capture.

## Local Claude configuration

Keep the API key in the repository-root `.env.claude.local` file. That file is
explicitly ignored by Git; `.env.claude.example` is the tracked template. Do not
put a real key in `.env.example`, shell history, Docker Compose YAML, or a source
file.

```powershell
.\scripts\init-claude-config.ps1
.\scripts\check-claude-config.ps1
# Existing Desktop mode (preserves active Runtime/Gateway/Lab containers):
.\scripts\start-desktop-claude.ps1
# Or a fresh all-Compose topology:
.\scripts\start-claude-ai.ps1
```

The initializer reads the key without printing it, generates distinct internal
tokens, resolves the immutable digest of the current local target image, and
writes the ignored local file. The checker validates required values, JSON
catalogs, and Git-ignore protection without calling Anthropic. Start scripts
pass the local file to Docker Compose with `--env-file`; the first provider
request is made only when a user later creates, reviews, or grades a Lab.

The local catalog uses the real `codegate/local-target` image digest and keeps
package/artifact catalogs empty. This supports non-CVE prompt-based Labs and
fails closed for explicit CVE requests until a matching reviewed component or
artifact is published. Before enabling a real environment builder, publish and
sign reviewed base/component images and use a private output repository. The
three AI service provider URLs continue to point to the internal model gateway;
no application-side contract changes when the upstream provider changes.
