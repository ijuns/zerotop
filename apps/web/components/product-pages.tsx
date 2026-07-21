"use client";

import type { Lab, RuntimeRun, ValidationResult } from "../lib/api";

function titleOf(lab: Lab) {
  return lab.title || lab.name || "이름 없는 Lab";
}

function teamOf(lab: Lab) {
  return lab.team || lab.teamType || "blue";
}

function imageOf(lab: Lab) {
  return lab.desktopImage || lab.environment || "ubuntu";
}

function uniqueCves(lab: Lab | null) {
  if (!lab) return [];
  return [...new Set([
    ...(lab.target?.cveIds || []),
    ...(lab.target?.expectedCves || []),
  ].filter((value): value is string => typeof value === "string"))];
}

export function ProductHome({
  labs,
  loading,
  onCreate,
  onOpenCourse,
}: {
  labs: Lab[];
  loading: boolean;
  onCreate: () => void;
  onOpenCourse: (lab: Lab) => void;
}) {
  const featured = labs.slice(0, 3);
  return (
    <div className="zt-home">
      <section className="zt-hero">
        <div className="zt-hero__copy">
          <span className="zt-pill">ZERO-DAY TRAINING ORCHESTRATION PLATFORM</span>
          <h1>오늘의 위협을,<br /><em>오늘의 실습으로.</em></h1>
          <p>공개 CVE와 검증된 보안 권고를 강의, 격리 환경, 평가 과제로 전환합니다. AI가 설계하고 정책 엔진과 샌드박스가 자동 검증합니다.</p>
          <div className="zt-hero__actions">
            <button className="primary-button" type="button" onClick={onCreate}>✦ AI Lab 생성하기</button>
            {featured[0] && <button className="zt-button-ghost" type="button" onClick={() => onOpenCourse(featured[0])}>최신 과정 둘러보기 →</button>}
          </div>
          <div className="zt-trust-row"><span>✓ 검증된 위협 정보</span><span>✓ 실행별 격리 환경</span><span>✓ 족보 없는 동적 평가</span></div>
        </div>
        <div className="zt-pipeline" aria-label="위협 정보에서 실습 환경으로 전환되는 과정">
          <header><span>THREAT-TO-LAB PIPELINE</span><b>LIVE</b></header>
          <div className="zt-source"><span>CVE</span><div><small>PUBLIC INTELLIGENCE</small><strong>공개 CVE · PoC · 보안 권고</strong></div><em>수집</em></div>
          <div className="zt-flow-line" aria-hidden="true"><i /><i /><i /></div>
          <div className="zt-pipeline__steps">
            <div><b>01</b><strong>AI 설계</strong><small>LabSpec 초안</small></div>
            <div><b>02</b><strong>안전 검증</strong><small>격리 · 출처 · 정책</small></div>
            <div><b>03</b><strong>동적 변형</strong><small>환경 · 문제 · 변수</small></div>
          </div>
          <div className="zt-package"><span>ZT</span><div><small>SIGNED LAB PACKAGE</small><strong>강의 + Range + 평가</strong></div><b>READY</b></div>
        </div>
      </section>

      <section className="zt-section">
        <div className="zt-section__heading"><div><span>LATEST VERIFIED LABS</span><h2>검증을 마친 최신 훈련</h2></div><button type="button" onClick={onCreate}>새 Lab 만들기 →</button></div>
        {loading ? <div className="zt-course-grid">{[0, 1, 2].map((item) => <div className="zt-course-card zt-course-card--loading" key={item} />)}</div> : featured.length === 0 ? (
          <div className="zt-empty"><strong>아직 생성된 Lab이 없습니다.</strong><span>AI Lab Builder에서 첫 훈련을 만들어 보세요.</span><button className="primary-button" type="button" onClick={onCreate}>첫 Lab 생성</button></div>
        ) : (
          <div className="zt-course-grid">
            {featured.map((lab) => {
              const cves = uniqueCves(lab);
              return <button className={`zt-course-card zt-course-card--${teamOf(lab)}`} type="button" onClick={() => onOpenCourse(lab)} key={lab.id}>
                <span className="zt-course-card__visual"><b>{cves[0] || (teamOf(lab) === "blue" ? "BLUE" : "RED")}</b><i>{teamOf(lab).toUpperCase()} TEAM</i></span>
                <span className="zt-course-card__body"><small>{imageOf(lab).toUpperCase()} · {lab.status || lab.validationStatus || "DRAFT"}</small><strong>{titleOf(lab)}</strong><em>{lab.description || lab.scenario?.summary || "AI가 생성한 동적 사이버보안 훈련"}</em><span>{lab.questions?.length || 0}개 평가 · {(lab.scenario?.logSources || []).length}개 로그 소스</span></span>
              </button>;
            })}
          </div>
        )}
      </section>

      <section className="zt-difference">
        <div><span>DYNAMIC BY DESIGN</span><h2>정답이 고정되지 않는<br />최신 위협 대응 훈련</h2><p>기존 콘텐츠를 반복하는 대신, AI가 환경 변수와 공격 경로, 증거와 평가를 매 실행에 맞게 구성합니다.</p></div>
        <div className="zt-compare"><div><small>기존 플랫폼</small><span>사람이 만든 고정 문제</span><strong>공개된 Write-up</strong></div><i>→</i><div className="is-zerotop"><small>ZeroTOP</small><span>AI가 생성하는 동적 시나리오</span><strong>자동 안전성 검증</strong></div></div>
      </section>

      <section className="zt-audience-grid">
        <div><small>B2C</small><strong>보안 인재 · 연구자</strong><span>최신 CVE 포트폴리오와 개인 역량 리포트</span></div>
        <div><small>B2B</small><strong>기업 보안 조직</strong><span>조직 대응 역량과 취약 영역의 객관적 측정</span></div>
        <div><small>B2G</small><strong>공공 · 교육 기관</strong><span>격리된 실전 훈련과 운영 정책의 중앙 관리</span></div>
      </section>
    </div>
  );
}

export function CourseOverview({
  lab,
  run,
  canDeploy,
  busy,
  onReview,
  onDeploy,
  onOpenWorkspace,
}: {
  lab: Lab | null;
  run: RuntimeRun | null;
  canDeploy: boolean;
  busy: boolean;
  onReview: () => void;
  onDeploy: () => void;
  onOpenWorkspace: () => void;
}) {
  if (!lab) {
    return <section className="zt-empty zt-empty--page"><strong>과정을 선택해 주세요.</strong><span>홈의 최신 Lab 또는 설계 · 검증의 Lab 라이브러리에서 과정을 선택할 수 있습니다.</span><button className="primary-button" type="button" onClick={onReview}>Lab 선택하기</button></section>;
  }
  const sections = lab.learning?.sections || [];
  const objectives = lab.learning?.objectives || [];
  const cves = uniqueCves(lab);
  const ready = run?.status.toLowerCase() === "ready";
  return (
    <div className="zt-course-page">
      <section className="zt-course-hero">
        <div><span>{teamOf(lab).toUpperCase()} TEAM · {imageOf(lab).toUpperCase()}</span><h1>{titleOf(lab)}</h1><p>{lab.description || lab.scenario?.summary || lab.prompt || "AI가 구성한 실전형 사이버보안 과정입니다."}</p><div>{cves.map((cve) => <b key={cve}>{cve}</b>)}<b>{lab.questions?.length || 0} QUESTIONS</b></div></div>
        <aside><small>VERIFIED LAB</small><strong>{lab.validationStatus || lab.status || "DRAFT"}</strong><span>강의 · 격리 환경 · 자동 평가</span></aside>
      </section>
      <nav className="zt-learning-nav"><a href="#zt-lecture"><b>01</b> 강의 자료</a><a href="#zt-environment"><b>02</b> 실습 환경</a><a href="#zt-assessment"><b>03</b> 자동 평가</a></nav>

      <section className="zt-course-layout" id="zt-lecture">
        <aside className="zt-outline"><strong>커리큘럼</strong>{(sections.length ? sections : [{ title: "위협과 영향 조건" }, { title: "공격 흐름과 탐지" }, { title: "완화 조치 검증" }]).map((section, index) => <div className={index === 0 ? "is-active" : ""} key={section.id || `${section.title}-${index}`}><span>{String(index + 1).padStart(2, "0")}</span><p>{section.title || `학습 섹션 ${index + 1}`}<small>{10 + index * 5}분</small></p></div>)}</aside>
        <div className="zt-lecture"><span>01 · LEARNING MATERIAL</span><h2>{sections[0]?.title || "위협과 영향 조건 이해"}</h2><p>{sections[0]?.bodyMarkdown || lab.scenario?.summary || "공개된 보안 권고와 관측 가능한 증거를 기반으로 영향 조건, 공격 흐름과 대응 방법을 학습합니다."}</p><div className="zt-objectives"><strong>이 과정에서 확인할 것</strong>{(objectives.length ? objectives : ["영향을 받는 조건과 자산 식별", "공격·탐지 증거의 상관관계 분석", "완화 조치 적용 후 재검증"]).map((item) => <span key={item}>✓ {item}</span>)}</div></div>
      </section>

      <section className="zt-environment-card" id="zt-environment">
        <div><small>02 · ISOLATED RANGE</small><h2>{imageOf(lab) === "kali" ? "Kali Attack Box" : "Ubuntu SOC Workstation"}</h2><p>실행별 전용 네트워크와 대상 서버를 배포하고 브라우저 데스크톱 또는 OpenVPN으로 접속합니다.</p></div>
        <div className="zt-env-facts"><span><small>DESKTOP</small><strong>{imageOf(lab).toUpperCase()}</strong></span><span><small>ACCESS</small><strong>{lab.accessMethod || "browser_desktop"}</strong></span><span><small>SESSION</small><strong>{run ? run.status.toUpperCase() : "NOT STARTED"}</strong></span></div>
        {run ? <button className="primary-button" type="button" onClick={onOpenWorkspace}>{ready ? "워크스페이스 열기" : "배포 상태 확인"} →</button> : canDeploy ? <button className="primary-button" type="button" onClick={onDeploy} disabled={busy}>{busy ? "환경 배포 중" : "개인 환경 배포"} →</button> : <button className="zt-button-ghost zt-button-ghost--light" type="button" onClick={onReview}>설계 · 검증 확인 →</button>}
      </section>

      <section className="zt-assessment-preview" id="zt-assessment">
        <header><div><small>03 · AUTO-GENERATED ASSESSMENT</small><h2>실습 결과를 증거로 평가합니다.</h2></div><b>{lab.questions?.length || 0}문제</b></header>
        <div>{(lab.questions || []).slice(0, 4).map((question, index) => <article key={question.id}><span>{String(index + 1).padStart(2, "0")}</span><div><small>{question.type.replaceAll("_", " ").toUpperCase()} · {question.points}점</small><strong>{question.prompt}</strong></div></article>)}</div>
        <button className="primary-button" type="button" onClick={run ? onOpenWorkspace : canDeploy ? onDeploy : onReview}>{run ? "실습 문제 풀기" : canDeploy ? "환경 배포 후 시작" : "검증 상태 확인"} →</button>
      </section>
    </div>
  );
}

export function ScenarioStudio({
  labs,
  lab,
  validation,
  onSelect,
  onPreview,
  onCreateVariant,
}: {
  labs: Lab[];
  lab: Lab | null;
  validation?: ValidationResult;
  onSelect: (lab: Lab) => void;
  onPreview: () => void;
  onCreateVariant: () => void;
}) {
  if (!lab) return null;
  const chain = lab.scenario?.attackChain || [];
  const sources = lab.scenario?.logSources || [];
  const sections = lab.learning?.sections || [];
  const decision = String(validation?.decision || lab.validationStatus || lab.status || "draft").toUpperCase();
  return (
    <section className="zt-studio" aria-labelledby="scenario-studio-title">
      <aside className="zt-studio__library">
        <header><div><span>SCENARIO LIBRARY</span><h2 id="scenario-studio-title">시나리오 구성</h2></div><b>자동 저장</b></header>
        <div>{labs.slice(0, 6).map((item) => <button className={item.id === lab.id ? "is-active" : ""} type="button" onClick={() => onSelect(item)} key={item.id}><span>{teamOf(item) === "blue" ? "BL" : "RD"}</span><p><strong>{titleOf(item)}</strong><small>{item.scenario?.attackChain?.length || 0} ATT&CK · {item.scenario?.logSources?.length || 0} LOG</small></p></button>)}</div>
        <button className="zt-generate-variant" type="button" onClick={onCreateVariant}><span>✦</span><p><strong>AI 시나리오 변형</strong><small>현재 Lab을 기반으로 새 변수 준비</small></p></button>
      </aside>
      <div className="zt-studio__detail">
        <header><div><span>{teamOf(lab).toUpperCase()} SCENARIO · {decision}</span><h2>{titleOf(lab)}</h2><p>{lab.scenario?.summary || lab.description || "AI가 구성한 공격·방어 시나리오입니다."}</p></div><div><button className="zt-button-ghost zt-button-ghost--light" type="button" onClick={onPreview}>과정 미리보기</button></div></header>

        <section className="zt-attack-chain"><strong>MITRE ATT&CK CHAIN</strong><div>{chain.length ? chain.map((item, index) => <article key={`${item.id}-${index}`}><span>{item.id || `STEP-${index + 1}`}</span><strong>{item.name || "공격 단계"}</strong><small>{item.tactic || "tactic"}</small>{index < chain.length - 1 && <i>→</i>}</article>) : <p>공격 체인이 생성되면 전술과 기술 흐름이 표시됩니다.</p>}</div></section>

        <div className="zt-perspectives">
          <section className="is-red"><header><span>RED</span><strong>공격 흐름</strong></header>{(chain.length ? chain.slice(0, 3).map((item) => item.name || item.id || "공격 단계") : ["초기 접근 경로 확인", "의도된 취약 동작 재현", "영향 범위와 증거 기록"]).map((item, index) => <p key={`${item}-${index}`}><b>{String(index + 1).padStart(2, "0")}</b>{item}</p>)}</section>
          <section className="is-blue"><header><span>BLUE</span><strong>탐지 · 대응 포인트</strong></header>{(sources.length ? sources.slice(0, 3) : ["Endpoint telemetry", "Network events", "Authentication logs"]).map((item, index) => <p key={`${item}-${index}`}><b>{String(index + 1).padStart(2, "0")}</b>{item} 분석</p>)}</section>
        </div>

        <div className="zt-quality-row"><span><b>✓</b> 출처 기반 설계</span><span><b>✓</b> 로그 소스 {sources.length}종</span><span><b>✓</b> 공격 체인 {chain.length}단계</span><span><b>✓</b> 고위험 환경 AI 자동 판정</span></div>
        <section className="zt-studio-bottom"><div><span>VALIDATION PIPELINE</span><div className="zt-validation-flow">{["출처 분석", "격리 빌드", "AI 위험 분석", "동작 검증", "정책 판정", "서명 · 게시"].map((item, index) => <p className={decision.includes("PASS") || decision.includes("APPROV") || index < 4 ? "is-done" : ""} key={item}><b>{index + 1}</b><strong>{item}</strong></p>)}</div></div><div><span>CURRICULUM</span>{(sections.length ? sections : [{ title: "위협과 영향 조건" }, { title: "공격·탐지 실습" }, { title: "완화 조치 검증" }]).slice(0, 5).map((section, index) => <p key={section.id || `${section.title}-${index}`}><b>{String(index + 1).padStart(2, "0")}</b>{section.title || `학습 단계 ${index + 1}`}</p>)}</div></section>
      </div>
    </section>
  );
}
