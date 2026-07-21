"use client";

import { type FormEvent, useEffect, useMemo, useState } from "react";

import {
  api,
  errorMessage,
  type ElkSearchHit,
  type ElkSearchResult,
  type LabQuestion,
} from "../lib/api";

const SENSITIVE_FIELD = /(?:password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)/i;

function redacted(value: unknown, depth = 0): unknown {
  if (depth > 6) return "[depth limited]";
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => redacted(item, depth + 1));
  if (typeof value === "object" && value !== null) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .slice(0, 100)
        .map(([key, item]) => [key, SENSITIVE_FIELD.test(key) ? "[REDACTED]" : redacted(item, depth + 1)]),
    );
  }
  return value;
}

function safePreview(source: Record<string, unknown>) {
  const text = JSON.stringify(redacted(source), null, 2);
  return text.length > 8_000 ? `${text.slice(0, 8_000)}\n… [preview truncated]` : text;
}

export function ElkSearchPanel({
  runId,
  ready,
  locked = false,
  questions,
  appliedEvidenceIds,
  onApply,
}: {
  runId: string | null;
  ready: boolean;
  locked?: boolean;
  questions: LabQuestion[];
  appliedEvidenceIds: string[];
  onApply(questionId: string, query: string, evidenceIds: string[]): void;
}) {
  const elkQuestions = useMemo(
    () => questions.filter((question) => question.type === "elk_search"),
    [questions],
  );
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<ElkSearchResult | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [targetQuestionId, setTargetQuestionId] = useState("");
  const [state, setState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const [appliedNotice, setAppliedNotice] = useState<string | null>(null);

  useEffect(() => {
    setQuery("");
    setResult(null);
    setSelectedIds([]);
    setState("idle");
    setError(null);
    setAppliedNotice(null);
  }, [runId]);

  useEffect(() => {
    if (!elkQuestions.some((question) => question.id === targetQuestionId)) {
      setTargetQuestionId(elkQuestions[0]?.id || "");
    }
  }, [elkQuestions, targetQuestionId]);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const normalized = query.trim();
    if (!runId || !ready || locked || normalized.length === 0 || state === "loading") return;
    setState("loading");
    setError(null);
    setAppliedNotice(null);
    try {
      const next = await api.searchElk(runId, normalized, 50);
      setResult(next);
      setSelectedIds((current) => current.filter((id) => next.hits.some((hit) => hit.id === id)));
      setState("ready");
    } catch (reason) {
      setResult(null);
      setError(errorMessage(reason));
      setState("error");
    }
  };

  const toggleHit = (hit: ElkSearchHit) => {
    if (locked) return;
    setSelectedIds((current) =>
      current.includes(hit.id)
        ? current.filter((id) => id !== hit.id)
        : [...current, hit.id],
    );
    setAppliedNotice(null);
  };

  const apply = () => {
    if (locked || !targetQuestionId || selectedIds.length === 0 || !query.trim()) return;
    onApply(targetQuestionId, query.trim(), selectedIds);
    setAppliedNotice(`${selectedIds.length}개 증거 ID를 ELK 답안에 반영했습니다.`);
  };

  return (
    <section className="panel elk-console" aria-labelledby="elk-console-title">
      <div className="panel-heading panel-heading--data">
        <div><span className="panel-kicker">RUN-SCOPED ELK</span><h2 id="elk-console-title">ELK 로그 검색</h2></div>
        <span className="data-count">{result ? `${result.total.toLocaleString("ko-KR")}건 · ${result.took}ms` : "BLUE TEAM"}</span>
      </div>

      {!runId ? (
        <div className="elk-console__state"><strong>배포된 실행 환경이 없습니다</strong><p>블루팀 Lab을 배포하면 해당 Run에 격리된 ELK 인덱스를 검색할 수 있습니다.</p></div>
      ) : !ready ? (
        <div className="elk-console__state" role="status"><span className="spinner" aria-hidden="true" /><div><strong>ELK 인덱스를 준비하고 있습니다</strong><p>실행 환경이 ready 상태가 되면 검색을 시작할 수 있습니다.</p></div></div>
      ) : (
        <>
          <form className="elk-search-form" onSubmit={(event) => void submit(event)} role="search">
            <label htmlFor="elk-query">KQL / Lucene 검색 쿼리</label>
            <div><input id="elk-query" type="search" value={query} onChange={(event) => setQuery(event.target.value)} maxLength={1000} placeholder="예: event.category:process AND process.name:powershell.exe" autoComplete="off" disabled={locked} /><button className="primary-button" type="submit" disabled={locked || !query.trim() || state === "loading"}>{state === "loading" ? <><span className="spinner" aria-hidden="true" /> 검색 중</> : "검색"}</button></div>
            <small>검색은 현재 Run의 인덱스에만 적용되며 쿼리 원문은 저장하지 않고 감사 로그에는 해시만 남깁니다.</small>
          </form>

          {state === "error" && <div className="alert alert--error elk-console__alert" role="alert"><strong>로그를 검색하지 못했습니다.</strong><span>{error}</span></div>}
          {state === "ready" && result?.hits.length === 0 && <div className="elk-console__state elk-console__state--compact"><strong>검색 결과가 없습니다</strong><p>필드명, 시간 범위와 검색 조건을 다시 확인해 주세요.</p></div>}
          {result && result.hits.length > 0 && (
            <>
              <div className="elk-result-toolbar">
                <span>표시 {result.hits.length.toLocaleString("ko-KR")}건 · 선택 {selectedIds.length.toLocaleString("ko-KR")}건</span>
                <button className="text-button" type="button" disabled={locked} onClick={() => setSelectedIds(selectedIds.length === result.hits.length ? [] : result.hits.map((hit) => hit.id))}>{selectedIds.length === result.hits.length ? "전체 해제" : "전체 선택"}</button>
              </div>
              <div className="elk-results">
                {result.hits.map((hit) => {
                  const selected = selectedIds.includes(hit.id);
                  const applied = appliedEvidenceIds.includes(hit.id);
                  return (
                    <article className={`${selected ? "elk-hit is-selected" : "elk-hit"}${applied ? " is-applied" : ""}`} key={hit.id}>
                      <label><input type="checkbox" checked={selected} disabled={locked} onChange={() => toggleHit(hit)} /><span className="custom-check" aria-hidden="true">✓</span><span><strong>{hit.id}</strong><small>{applied ? "현재 답안에 반영됨" : hit.score === null ? "검색 일치" : `score ${hit.score}`}</small></span></label>
                      <pre tabIndex={0}>{safePreview(hit.source)}</pre>
                    </article>
                  );
                })}
              </div>
              <div className="elk-evidence-apply">
                {elkQuestions.length > 1 ? (
                  <label><span>반영할 문제</span><select value={targetQuestionId} onChange={(event) => setTargetQuestionId(event.target.value)}>{elkQuestions.map((question) => <option key={question.id} value={question.id}>{question.prompt}</option>)}</select></label>
                ) : <span>{elkQuestions[0]?.prompt || "ELK 검색형 문제가 없습니다."}</span>}
                <button className="secondary-button" type="button" disabled={locked || selectedIds.length === 0 || !targetQuestionId} onClick={apply}>{locked ? "제출 완료" : "선택한 증거를 답안에 반영"}</button>
              </div>
              {appliedNotice && <div className="alert alert--info elk-console__alert" role="status"><strong>증거가 연결되었습니다.</strong><span>{appliedNotice}</span></div>}
            </>
          )}
        </>
      )}
    </section>
  );
}
