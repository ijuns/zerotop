from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


MAX_CAPTURE_BYTES = 2_000_000


def require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} is not an object")
    return value


def main() -> int:
    if len(sys.argv) not in {2, 3}:
        raise SystemExit(
            "usage: analyze_anthropic_capture.py RAW_RESPONSE [ANALYSIS_JSON]"
        )

    capture_path = Path(sys.argv[1]).resolve()
    raw = capture_path.read_bytes()
    if len(raw) > MAX_CAPTURE_BYTES:
        raise ValueError("capture exceeds the bounded response size")

    response = require_object(json.loads(raw), "Anthropic response")
    content = response.get("content")
    if not isinstance(content, list) or len(content) != 1:
        raise ValueError("Anthropic response does not contain one content block")
    block = require_object(content[0], "Anthropic content block")
    text = block.get("text")
    if block.get("type") != "text" or not isinstance(text, str):
        raise ValueError("Anthropic response content is not text")

    envelope = require_object(json.loads(text), "generation envelope")
    payload = envelope.get("payload")
    if set(envelope) != {"payload"} or not isinstance(payload, str):
        raise ValueError("generation envelope does not contain only payload")

    payload_bytes = payload.encode("utf-8")
    analysis: dict[str, Any] = {
        "providerResponseId": response.get("id"),
        "stopReason": response.get("stop_reason"),
        "responseBytes": len(raw),
        "payloadBytes": len(payload_bytes),
        "payloadCharacters": len(payload),
        "payloadSha256": hashlib.sha256(payload_bytes).hexdigest(),
        "validJson": False,
    }

    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError as error:
        start = max(0, error.pos - 120)
        end = min(len(payload), error.pos + 120)
        offending = payload[error.pos] if error.pos < len(payload) else None
        analysis.update(
            {
                "parseError": error.msg,
                "errorOffset": error.pos,
                "errorLine": error.lineno,
                "errorColumn": error.colno,
                "offendingCharacter": offending,
                "offendingCodePoint": ord(offending) if offending else None,
                "contextStartOffset": start,
                "contextEndOffset": end,
                "context": payload[start:end],
            }
        )
    else:
        analysis["validJson"] = True
        analysis["decodedType"] = type(decoded).__name__

    rendered = json.dumps(analysis, ensure_ascii=False, indent=2)
    if len(sys.argv) == 3:
        output_path = Path(sys.argv[2]).resolve()
        output_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
