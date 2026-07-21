from __future__ import annotations

import os
import secrets
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from app.domain import DomainError, validate_lab_draft
from app.generation import GenerationError, generate_lab
from app.intel import IntelError, environment_nvd_client
from app.rubric import RubricError, grade_free_text
from app.review import ReviewError, review_validation
from app.validation_pipeline import validate_publish_candidate

app = FastAPI(title="ZeroTOP AI Service", version="1.0.0")
nvd_client = environment_nvd_client()


def require_internal_authorization(
    authorization: str | None = Header(default=None),
) -> None:
    mode = os.getenv("AI_AUTH_MODE", "internal")
    if mode == "dev":
        return
    if mode != "internal":
        raise HTTPException(status_code=503, detail="AI_AUTH_MODE is invalid")
    expected = os.getenv("AI_INTERNAL_TOKEN", "")
    if len(expected) < 24:
        raise HTTPException(status_code=503, detail="AI service authentication is not configured")
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if not secrets.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid internal service token")


class GenerateRequest(BaseModel):
    title: str = Field(min_length=3, max_length=120)
    prompt: str = Field(min_length=10, max_length=5000)
    team: Literal["blue", "red"]
    desktopImage: Literal["ubuntu", "kali"] | None = None
    accessMethod: Literal["browser_desktop", "openvpn", "both"] = "browser_desktop"
    questionTypes: list[str]
    cveIds: list[str] = Field(default_factory=list, max_length=20)


class ValidateRequest(BaseModel):
    lab: dict[str, Any]


class PublishValidateRequest(BaseModel):
    lab: dict[str, Any]
    evidence: dict[str, Any]


class ValidationReviewRequest(BaseModel):
    lab: dict[str, Any]
    evidence: dict[str, Any]


class FreeTextGradeRequest(BaseModel):
    runId: str = Field(min_length=1, max_length=63, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    questionId: str = Field(min_length=1, max_length=128)
    rubricId: str = Field(min_length=1, max_length=128)
    response: str = Field(min_length=10, max_length=20_000)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "authMode": os.getenv("AI_AUTH_MODE", "internal")}


@app.get(
    "/v1/intel/cves/{cve_id}",
    dependencies=[Depends(require_internal_authorization)],
)
async def cve_intel(cve_id: str) -> dict[str, Any]:
    try:
        return await nvd_client.resolve(cve_id)
    except IntelError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@app.post(
    "/v1/drafts/generate",
    dependencies=[Depends(require_internal_authorization)],
)
async def generate(request: GenerateRequest) -> dict[str, Any]:
    try:
        return await generate_lab(request.model_dump())
    except (DomainError, GenerationError) as exc:
        status = exc.status if isinstance(exc, GenerationError) else 422
        raise HTTPException(status_code=status, detail=str(exc)) from exc


@app.post("/v1/validate", dependencies=[Depends(require_internal_authorization)])
def validate(request: ValidateRequest) -> dict[str, Any]:
    return validate_lab_draft(request.lab)


@app.post(
    "/v1/publish-validation",
    dependencies=[Depends(require_internal_authorization)],
)
def publish_validate(request: PublishValidateRequest) -> dict[str, Any]:
    return validate_publish_candidate(request.lab, request.evidence)


@app.post(
    "/v1/review/validation",
    dependencies=[Depends(require_internal_authorization)],
)
async def validation_review(request: ValidationReviewRequest) -> dict[str, Any]:
    try:
        return await review_validation(request.model_dump())
    except ReviewError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc


@app.post(
    "/v1/grade/free-text",
    dependencies=[Depends(require_internal_authorization)],
)
async def free_text_grade(request: FreeTextGradeRequest) -> dict[str, Any]:
    try:
        return await grade_free_text(request.model_dump())
    except RubricError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
