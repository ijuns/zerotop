# ZeroTOP scenario log generator

This local-runtime component accepts the AI-validated telemetry fixture through
`SCENARIO_EVENTS_BASE64` plus the bounded `SCENARIO_GENERATION_BASE64` plan and
writes ECS-shaped NDJSON to the run-owned `/var/log/zerotop` volume. A compact
set of reviewed scenario signals is expanded to 1,200 events by default, with
normal authentication, process, network, file, web and administrative activity
interleaved around the attack timeline. Counts are constrained to 100-5,000.
It never executes model-produced shell commands or connects to external targets.

The production runtime can replace this development image with an approved
attack-emulation runner while preserving the same evidence and isolation
contract.
