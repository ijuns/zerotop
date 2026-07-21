from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from app.domain import BLUE_QUESTIONS, RED_QUESTIONS


class ContentContractError(ValueError):
    """Raised when a model-generated training package is not executable or gradable."""


def validate_generated_content(
    payload: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any]:
    learning = _object(payload.get("learning"), "learning")
    sections = _list(learning.get("sections"), "learning.sections", 2, 12)
    for index, section_value in enumerate(sections):
        section = _object(section_value, f"learning.sections[{index}]")
        _identifier(section.get("id"), f"learning.sections[{index}].id")
        _text(section.get("title"), f"learning.sections[{index}].title", 3, 120)
        _text(section.get("bodyMarkdown"), f"learning.sections[{index}].bodyMarkdown", 20, 20_000)

    team = str(request.get("team"))
    requested_types = list(dict.fromkeys(request.get("questionTypes") or []))
    questions = _list(payload.get("questions"), "questions", len(requested_types), 20)
    grading = _list(payload.get("gradingQuestions"), "gradingQuestions", len(questions), len(questions))
    public_by_id: dict[str, dict[str, Any]] = {}
    types_seen: set[str] = set()
    for index, question_value in enumerate(questions):
        question = _object(question_value, f"questions[{index}]")
        question_id = _identifier(question.get("id"), f"questions[{index}].id")
        if question_id in public_by_id:
            raise ContentContractError("question IDs must be unique")
        question_type = str(question.get("type"))
        if question_type not in requested_types:
            raise ContentContractError("a generated question changed the requested type scope")
        if _contains_answer_key(question):
            raise ContentContractError("a public question contains answer material")
        _text(question.get("prompt"), f"questions[{index}].prompt", 10, 2_000)
        points = question.get("points")
        if isinstance(points, bool) or not isinstance(points, int) or points < 1 or points > 1_000:
            raise ContentContractError(f"questions[{index}].points is invalid")
        if question_type in {"single_choice", "multiple_choice"}:
            options = _list(question.get("options"), f"questions[{index}].options", 2, 8)
            option_ids = set()
            for option_index, option_value in enumerate(options):
                option = _object(option_value, f"questions[{index}].options[{option_index}]")
                option_id = _identifier(option.get("id"), "option.id")
                _text(option.get("label"), "option.label", 1, 500)
                option_ids.add(option_id)
            if len(option_ids) != len(options):
                raise ContentContractError("question option IDs must be unique")
        public_by_id[question_id] = question
        types_seen.add(question_type)

    if set(requested_types) != types_seen:
        raise ContentContractError("every requested question type must be generated")
    if team == "blue" and types_seen != BLUE_QUESTIONS:
        raise ContentContractError("blue-team questions must be ELK plus MITRE ATT&CK")
    if team == "red" and not types_seen.issubset(RED_QUESTIONS):
        raise ContentContractError("red-team questions contain an unsupported type")

    grading_ids: set[str] = set()
    telemetry_ids = _telemetry_ids(payload, team)
    attack_ids = _attack_ids(payload)
    for index, grading_value in enumerate(grading):
        grade = _object(grading_value, f"gradingQuestions[{index}]")
        question_id = _identifier(grade.get("id"), f"gradingQuestions[{index}].id")
        public = public_by_id.get(question_id)
        if public is None or grade.get("type") != public.get("type") or grade.get("points") != public.get("points"):
            raise ContentContractError("public and hidden question contracts do not match")
        answer = _object(grade.get("answerKey"), f"gradingQuestions[{index}].answerKey")
        _validate_answer_key(str(grade.get("type")), answer, public, telemetry_ids, attack_ids)
        grading_ids.add(question_id)
    if grading_ids != set(public_by_id):
        raise ContentContractError("every public question requires one hidden grading contract")

    build_spec = _object(payload.get("environmentBuildSpec"), "environmentBuildSpec")
    _validate_build_spec(build_spec, payload, request)
    return payload


def prompt_digest(prompt: str) -> str:
    return f"sha256:{hashlib.sha256(prompt.encode('utf-8')).hexdigest()}"


def _validate_build_spec(
    spec: dict[str, Any], payload: dict[str, Any], request: dict[str, Any]
) -> None:
    if spec.get("schemaVersion") != 1 or spec.get("team") != request.get("team"):
        raise ContentContractError("environmentBuildSpec version or team is invalid")
    source = _object(spec.get("source"), "environmentBuildSpec.source")
    if source.get("promptDigest") != prompt_digest(str(request.get("prompt", ""))):
        raise ContentContractError("environmentBuildSpec prompt digest is invalid")
    cve_ids = _list(source.get("cveIds", []), "source.cveIds", 0, 20)
    if any(not re.fullmatch(r"CVE-\d{4}-\d{4,7}", str(item).upper()) for item in cve_ids):
        raise ContentContractError("environmentBuildSpec contains an invalid CVE ID")
    target = _object(spec.get("target"), "environmentBuildSpec.target")
    _identifier(target.get("name"), "target.name")
    if not re.fullmatch(r"[a-z0-9.-]+(?::\d+)?/[a-z0-9._/-]+@sha256:[a-f0-9]{64}", str(target.get("baseImage", "")), re.I):
        raise ContentContractError("target.baseImage must be digest-pinned")
    if not re.fullmatch(r"[a-z0-9.-]+(?::\d+)?/[a-z0-9._/-]+", str(target.get("outputRepository", "")), re.I):
        raise ContentContractError("target.outputRepository is invalid")
    service = _object(target.get("service"), "target.service")
    port = service.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ContentContractError("target.service.port is invalid")
    protocol = service.get("protocol")
    if protocol not in {"http", "tcp"}:
        raise ContentContractError("target.service.protocol must be http or tcp")
    packages = _list(target.get("packages", []), "target.packages", 0, 100)
    for package_value in packages:
        package = _object(package_value, "target package")
        _identifier(package.get("name"), "package.name")
        _text(package.get("version"), "package.version", 1, 100)
    artifacts = _list(target.get("artifacts", []), "target.artifacts", 0, 20)
    for artifact_value in artifacts:
        artifact = _object(artifact_value, "target artifact")
        url = str(artifact.get("url", ""))
        if not url.startswith("https://") or len(url) > 2_000:
            raise ContentContractError("artifact.url must use HTTPS")
        if not re.fullmatch(r"[a-f0-9]{64}", str(artifact.get("sha256", "")), re.I):
            raise ContentContractError("artifact.sha256 is invalid")
        destination = str(artifact.get("destination", ""))
        if not re.fullmatch(r"/opt/codegate/artifacts/[A-Za-z0-9._-]{1,128}", destination):
            raise ContentContractError("artifact.destination is invalid")
    functional = _list(target.get("functionalProbes"), "target.functionalProbes", 1, 20)
    vulnerable = _list(target.get("vulnerabilityProbes"), "target.vulnerabilityProbes", 1, 20)
    for probe_value in [*functional, *vulnerable]:
        _validate_probe(_object(probe_value, "target probe"), str(protocol))
    for probe_value in vulnerable:
        probe = _object(probe_value, "vulnerability probe")
        if not probe.get("cveId") and not probe.get("findingId"):
            raise ContentContractError("vulnerability probes require cveId or findingId")
    spec_learning = spec.get("learning")
    spec_questions = spec.get("questions")
    public_learning = _object(payload.get("learning"), "learning")
    expected_build_learning = {
        "title": public_learning.get("title"),
        "summary": public_learning.get("summary"),
        "sections": [
            {
                "id": _object(section, "learning section").get("id"),
                "title": _object(section, "learning section").get("title"),
                "markdown": _object(section, "learning section").get("bodyMarkdown"),
            }
            for section in _list(
                public_learning.get("sections"), "learning.sections", 2, 12
            )
        ],
    }
    if spec_learning != expected_build_learning or spec_questions != payload.get("questions"):
        raise ContentContractError("build learning/question projection is invalid")

    scenario = _object(payload.get("scenario"), "scenario")
    build_scenario = _object(spec.get("scenario"), "environmentBuildSpec.scenario")
    expected_techniques = [
        str(_object(item, "attackChain item").get("id"))
        for item in _list(scenario.get("attackChain"), "scenario.attackChain", 1, 50)
    ]
    if build_scenario != {
        "summary": scenario.get("summary"),
        "mitreTechniques": expected_techniques,
    }:
        raise ContentContractError("build scenario projection is invalid")

    grading_contract = _object(spec.get("grading"), "environmentBuildSpec.grading")
    hidden_refs = _list(
        grading_contract.get("hiddenRefs"),
        "environmentBuildSpec.grading.hiddenRefs",
        len(questions := _list(payload.get("questions"), "questions", 1, 20)),
        len(questions),
    )
    question_ids = {str(_object(item, "question").get("id")) for item in questions}
    referenced_ids: set[str] = set()
    for index, ref_value in enumerate(hidden_refs):
        ref = _object(ref_value, f"hiddenRefs[{index}]")
        question_id = str(ref.get("questionId", ""))
        if (
            set(ref) != {"questionId", "refId", "rubricDigest"}
            or question_id not in question_ids
            or not re.fullmatch(r"grading://[A-Za-z0-9][A-Za-z0-9._:/-]{0,190}", str(ref.get("refId", "")))
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", str(ref.get("rubricDigest", "")))
        ):
            raise ContentContractError("build hidden grading reference is invalid")
        referenced_ids.add(question_id)
    if referenced_ids != question_ids:
        raise ContentContractError("build hidden grading references are incomplete")


def _validate_probe(probe: dict[str, Any], protocol: str) -> None:
    _identifier(probe.get("id"), "probe.id")
    kind = probe.get("kind")
    if protocol == "http":
        if kind != "http" or probe.get("method") not in {"GET", "HEAD"}:
            raise ContentContractError("HTTP probes permit only GET or HEAD")
        path = str(probe.get("path", ""))
        if not path.startswith("/") or path.startswith("//") or "://" in path or "\\" in path or len(path) > 500:
            raise ContentContractError("probe.path is unsafe")
        statuses = _list(probe.get("expectedStatuses"), "probe.expectedStatuses", 1, 8)
        if any(isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599 for status in statuses):
            raise ContentContractError("probe.expectedStatuses is invalid")
        _markers(probe.get("bodyIncludes", []), "probe.bodyIncludes")
    elif protocol == "tcp":
        if kind != "tcp_banner":
            raise ContentContractError("TCP validation permits only passive banner probes")
        if not _markers(probe.get("bannerIncludes"), "probe.bannerIncludes"):
            raise ContentContractError("TCP banner probes require a marker")


def _validate_answer_key(
    question_type: str,
    answer: dict[str, Any],
    public: dict[str, Any],
    telemetry_ids: set[str],
    attack_ids: set[str],
) -> None:
    if question_type in {"single_choice", "multiple_choice"}:
        option_ids = {str(item.get("id")) for item in public.get("options", []) if isinstance(item, dict)}
        selected = _list(answer.get("optionIds"), "answerKey.optionIds", 1, len(option_ids))
        if not set(map(str, selected)).issubset(option_ids):
            raise ContentContractError("an answer key references an unknown option")
        if question_type == "single_choice" and len(selected) != 1:
            raise ContentContractError("single-choice answers require exactly one option")
    elif question_type == "mitre_attack":
        selected = set(map(str, _list(answer.get("techniqueIds"), "answerKey.techniqueIds", 1, 20)))
        if not selected.issubset(attack_ids):
            raise ContentContractError("a MITRE answer is outside the generated attack chain")
    elif question_type == "elk_search":
        selected = set(map(str, _list(answer.get("expectedEvidenceIds"), "answerKey.expectedEvidenceIds", 1, 100)))
        if not selected.issubset(telemetry_ids):
            raise ContentContractError("an ELK answer references missing telemetry evidence")
    elif question_type == "free_text":
        _identifier(answer.get("rubricId"), "answerKey.rubricId")
    else:
        raise ContentContractError("unsupported grading question type")


def _telemetry_ids(payload: dict[str, Any], team: str) -> set[str]:
    spec = _object(payload.get("environmentBuildSpec"), "environmentBuildSpec")
    telemetry = spec.get("telemetry")
    if team != "blue":
        return set()
    telemetry_object = _object(telemetry, "environmentBuildSpec.telemetry")
    events = _list(telemetry_object.get("events"), "telemetry.events", 1, 100)
    result: set[str] = set()
    for index, event_value in enumerate(events):
        event = _object(event_value, f"telemetry.events[{index}]")
        event_id = _identifier(event.get("id"), f"telemetry.events[{index}].id", 128)
        document = _object(event.get("document"), f"telemetry.events[{index}].document")
        if len(json.dumps(document, ensure_ascii=False).encode("utf-8")) > 32_000:
            raise ContentContractError("a telemetry event exceeds 32 KB")
        if "@timestamp" not in document or not isinstance(document.get("event"), dict) or not isinstance(document.get("threat"), dict):
            raise ContentContractError("blue telemetry events require ECS timestamp/event/threat fields")
        if _contains_answer_key(document):
            raise ContentContractError("telemetry contains answer or flag material")
        result.add(event_id)
    if len(result) != len(events):
        raise ContentContractError("telemetry event IDs must be unique")
    return result


def _attack_ids(payload: dict[str, Any]) -> set[str]:
    scenario = _object(payload.get("scenario"), "scenario")
    chain = _list(scenario.get("attackChain"), "scenario.attackChain", 1, 50)
    result = set()
    for item in chain:
        technique = str(_object(item, "attackChain item").get("id", "")).upper()
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            raise ContentContractError("scenario.attackChain contains an invalid ATT&CK ID")
        result.add(technique)
    return result


def _contains_answer_key(value: Any, depth: int = 0) -> bool:
    if depth > 12:
        return True
    if isinstance(value, list):
        return any(_contains_answer_key(item, depth + 1) for item in value)
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        if re.fullmatch(r"(?:answer|answerkey|correct(?:answer|option|options?)?|solution|flag)", str(key), re.I):
            return True
        if _contains_answer_key(item, depth + 1):
            return True
    return False


def _markers(value: Any, name: str) -> list[Any]:
    markers = _list(value, name, 0, 8)
    for marker in markers:
        _text(marker, name, 1, 200)
    return markers


def _identifier(value: Any, name: str, maximum: int = 80) -> str:
    result = _text(value, name, 1, maximum)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", result):
        raise ContentContractError(f"{name} is invalid")
    return result


def _text(value: Any, name: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ContentContractError(f"{name} is invalid")
    return value


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContentContractError(f"{name} must be an object")
    return value


def _list(value: Any, name: str, minimum: int, maximum: int) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ContentContractError(f"{name} must contain {minimum}-{maximum} entries")
    return value
