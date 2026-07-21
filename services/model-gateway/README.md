# Model gateway

This service is the only application component allowed to call the OpenAI API. It uses the Responses API with a strict JSON Schema, disables response storage, does not expose tools, and reconstructs the trusted LabSpec from operator-owned catalogs instead of accepting a model-authored build specification.

The production model is configured with the explicit `gpt-5.6-sol` model ID through `OPENAI_MODEL`. See the official [GPT-5.6 model page](https://developers.openai.com/api/docs/models/gpt-5.6) and [Structured Outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs).

## Privacy boundary

Do not send a user ID, email address, OIDC subject, organization ID, or any other direct identifier to the provider. A future end-user abuse correlation feature may add the Responses API `safety_identifier`, but only after the API derives a stable opaque value such as `base64url(HMAC-SHA256(provider-safety-key, user-id))` and the raw identifier is kept inside the Codegate trust boundary. The key must be separate from application signing keys and support rotation. Until that end-to-end path exists, the gateway intentionally omits `safety_identifier`.

## Required secrets

- `MODEL_GATEWAY_INTERNAL_TOKEN`: shared only with the AI service.
- `OPENAI_API_KEY`: injected only into this service.

Neither secret is logged or included in model input. The official API origin is fixed to `https://api.openai.com/v1` and redirects are rejected.
