import type { JsonObject, QuestionType, TeamType } from "./types.ts";

export const KOREAN_CONTENT_REVISION = "zerotop-ko-v3";

export interface GeneratedTrainingContent {
  scenarioSummary: string;
  logSources: string[];
  attackChain: Array<{ id: string; name: string; tactic: string }>;
  scenarioProfile: string;
  learning: JsonObject;
  publicQuestions: JsonObject[];
  gradingQuestions: JsonObject[];
  telemetryEvents: JsonObject[];
}

interface BlueScenarioProfile {
  id: "powershell_rce_exfiltration" | "credential_abuse" | "ransomware" | "webshell" | "generic_intrusion";
  summary: string;
  logSources: string[];
  attackChain: Array<{ id: string; name: string; tactic: string }>;
  executionLabel: string;
  impactLabel: string;
}

interface RedScenarioProfile {
  id: "web_application" | "credential_access" | "file_exposure" | "container_escape" | "generic_validation";
  summary: string;
  logSources: string[];
  attackChain: Array<{ id: string; name: string; tactic: string }>;
  surfaceLabel: string;
  validationFocus: string;
  defenderSignals: string;
  mitigationFocus: string;
}

/**
 * Development/local authoring content. Production AI output is validated
 * against the same shape, while this deterministic path keeps local Labs
 * useful when no external model provider is configured.
 */
export function buildTrainingContent(input: {
  team: TeamType;
  title: string;
  prompt: string;
  questionTypes: QuestionType[];
  mitreTechniques: string[];
  cveIds?: string[];
  now?: Date;
}): GeneratedTrainingContent {
  const cveIds = input.cveIds ?? [];
  const lower = `${input.title} ${input.prompt} ${cveIds.join(" ")}`.toLowerCase();
  const blueProfile = input.team === "blue" ? selectBlueProfile(lower) : null;
  const redProfile = input.team === "red" ? selectRedProfile(lower) : null;
  const profileAttackChain = blueProfile?.attackChain ?? redProfile?.attackChain ?? [];
  const attackChain = input.team === "red" && input.mitreTechniques.length > 0
    ? mergeRequestedTechniques(input.mitreTechniques, profileAttackChain)
    : [...profileAttackChain];
  if (attackChain.length === 0) {
    attackChain.push(
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
      { id: "T1059.004", name: "Unix Shell", tactic: "execution" },
    );
  }
  const techniques = attackChain.map((item) => item.id);
  const scenarioSummary = input.team === "blue"
    ? blueProfile!.summary
    : redProfile!.summary;
  const logSources = input.team === "blue"
    ? blueProfile!.logSources
    : redProfile!.logSources;
  const telemetryEvents = input.team === "blue"
    ? blueSignalEvents(input.now ?? new Date(), blueProfile!)
    : [];
  const learning = buildLearning({
    team: input.team,
    title: input.title,
    prompt: input.prompt,
    summary: scenarioSummary,
    logSources,
    profile: blueProfile,
    redProfile,
    cveIds,
  });
  const { publicQuestions, gradingQuestions } = buildQuestions(
    input.team,
    input.questionTypes,
    techniques,
    telemetryEvents,
    blueProfile,
    redProfile,
  );
  return {
    scenarioSummary,
    logSources,
    attackChain,
    scenarioProfile: blueProfile?.id ?? redProfile!.id,
    learning,
    publicQuestions,
    gradingQuestions,
    telemetryEvents,
  };
}

function buildLearning(input: {
  team: TeamType;
  title: string;
  prompt: string;
  summary: string;
  logSources: string[];
  profile: BlueScenarioProfile | null;
  redProfile: RedScenarioProfile | null;
  cveIds: string[];
}): JsonObject {
  const blue = input.team === "blue";
  if (!blue) {
    return buildRedLearning({
      title: input.title,
      prompt: input.prompt,
      profile: input.redProfile!,
      cveIds: input.cveIds,
    });
  }
  return {
    title: input.title,
    summary: input.summary,
    prerequisites: blue
      ? ["침해사고 대응 절차 기초", "Windows 이벤트 및 프로세스 개념", "Kibana Discover 기본 사용법"]
      : ["TCP/IP 및 HTTP 기초", "Linux 명령행 기초", "격리 환경의 범위 통제 원칙"],
    objectives: blue
      ? [
          "정상 운영 로그와 공격 신호를 구분하고 시간순 사건 흐름을 재구성합니다.",
          "ELK에서 KQL을 사용해 인증·프로세스·파일·네트워크 증거를 교차 검증합니다.",
          "관찰한 행위를 MITRE ATT&CK 전술과 기법 후보에 근거 기반으로 매핑합니다.",
          "초동 격리, 자격 증명 조치, 탐지 규칙 개선과 재발 방지 방안을 제안합니다.",
        ]
      : [
          "허용된 대상의 공격 표면과 취약 조건을 식별합니다.",
          "공격 단계별 행위가 남기는 방어 관측 지점을 설명합니다.",
          "발견 사항을 MITRE ATT&CK 및 완화 권고와 연결합니다.",
        ],
    sections: blue
      ? [
          {
            id: "threat-context",
            title: "시나리오 브리핑과 조사 범위",
            bodyMarkdown: `## ${input.title}\n\n${input.prompt}\n\n${input.summary}${input.cveIds.length > 0 ? `\n\n학습 대상 취약점: **${input.cveIds.join(", ")}**. 공개 식별자는 조사 범위를 정하는 참고 정보이며, 실제 영향 조건은 제공된 격리 환경의 서비스·로그 증거로 검증해야 합니다.` : ""}\n\n분석 범위는 제공된 격리 환경으로 제한합니다. 문제의 정답을 추측하기보다 서로 다른 로그 소스에서 동일한 사용자·호스트·프로세스·네트워크 흐름이 이어지는지 검증하세요.`,
          },
          {
            id: "evidence-model",
            title: "증거 모델과 타임라인 상관분석",
            bodyMarkdown: `이번 실습에는 ${input.logSources.join(", ")} 계열 로그가 섞여 있습니다. \`@timestamp\`를 기준으로 정렬한 뒤 \`host.name\`, \`user.name\`, \`process.entity_id\`, \`source.ip\`, \`destination.ip\`, \`file.path\`를 연결 키로 사용합니다. 단일 이벤트만으로 결론을 내리지 말고 앞뒤 이벤트와 정상 기준선을 함께 비교하세요.`,
          },
          {
            id: "investigation-workflow",
            title: "SOC 조사 워크플로",
            bodyMarkdown: `1. 전체 시간 범위와 데이터 수집 상태를 확인합니다.\n2. 인증 또는 외부 노출 지점에서 최초 이상 징후 후보를 찾습니다.\n3. 같은 호스트와 사용자에서 이어진 ${input.profile?.executionLabel ?? "후속 실행"} 관련 이벤트를 확인합니다.\n4. ${input.profile?.impactLabel ?? "영향 행위"} 전후의 파일·프로세스·네트워크 증거를 교차 검증합니다.\n5. 증거 ID와 사용한 쿼리를 기록하고 반증 가능한 정상 행위도 함께 검토합니다.`,
          },
          {
            id: "elk-kql-guidance",
            title: "ELK Discover와 KQL 검색 가이드",
            bodyMarkdown: "Kibana의 **Analytics → Discover**에서 실습 데이터 뷰를 선택합니다. 먼저 넓은 조건으로 후보를 찾고 필드를 하나씩 추가해 범위를 좁히세요. 예: `event.category:process AND host.name:*`, `event.category:authentication AND event.outcome:*`, `file.path:* AND user.name:*`. 쿼리 결과가 지나치게 적으면 시간 범위와 필드 존재 여부를 확인하고, 지나치게 많으면 호스트·사용자·프로세스 식별자를 조합합니다. 강의 예시는 검색 방법을 설명할 뿐 특정 증거 ID나 정답을 제공하지 않습니다.",
          },
          {
            id: "mitre-context",
            title: "MITRE ATT&CK 근거 기반 매핑",
            bodyMarkdown: "ATT&CK 매핑은 도구 이름이 아니라 관찰한 **행위와 목적**을 기준으로 수행합니다. 인증, 명령 실행, 수집, 압축, 외부 전송처럼 단계별 증거를 먼저 기술하고, 해당 전술에서 가능한 기법 후보를 비교하세요. 하나의 이벤트가 여러 후보와 연관될 수 있으므로 타임라인 전체와 데이터 소스를 근거로 최종 선택합니다.",
          },
          {
            id: "response-remediation",
            title: "초동 대응과 재발 방지",
            bodyMarkdown: "조사 결과에 따라 영향을 받은 계정과 호스트를 우선 격리하고, 활성 세션 및 자격 증명을 재검토합니다. 의심 프로세스·파일·네트워크 지표를 탐지 규칙으로 전환한 뒤 과거 로그에 소급 적용합니다. 취약 서비스 패치, 최소 권한, 스크립트 로깅 강화, 외부 통신 통제를 적용하고 동일 시나리오가 재현되지 않는지 검증합니다.",
          },
        ]
      : [
          {
            id: "threat-context",
            title: "시나리오와 허용 범위",
            bodyMarkdown: `## ${input.title}\n\n${input.prompt}\n\n${input.summary}${input.cveIds.length > 0 ? `\n\n학습 대상 취약점: **${input.cveIds.join(", ")}**. 공개 식별자만으로 성공을 가정하지 말고 제공 환경에서 영향 조건을 검증하세요.` : ""}\n\n제공된 대상과 허용된 접근 방식만 사용하며 외부 시스템으로 범위를 확장하지 않습니다.`,
          },
          {
            id: "attack-workflow",
            title: "공격 표면 검증 절차",
            bodyMarkdown: "서비스 식별, 취약 조건 확인, 제한된 검증, 영향 분석 순서로 진행합니다. 각 단계에서 사용한 가정과 관찰 결과를 기록하고 불필요한 파괴 행위는 수행하지 않습니다.",
          },
          {
            id: "defender-visibility",
            title: "방어 관점의 관측 지점",
            bodyMarkdown: "웹 요청, 인증, 프로세스 실행, 파일 변경, 네트워크 연결 중 어떤 지점에서 행위가 관찰되는지 정리합니다. 공격 성공 여부뿐 아니라 탐지와 차단이 가능한 통제 지점을 함께 설명합니다.",
          },
          {
            id: "mitre-context",
            title: "MITRE ATT&CK 매핑 원칙",
            bodyMarkdown: "도구 이름만으로 기법을 선택하지 말고 실제로 수행된 행위, 대상, 목적을 근거로 전술과 기법 후보를 비교합니다. 특정 정답 ID는 강의에서 제공하지 않습니다.",
          },
          {
            id: "remediation",
            title: "완화와 재검증",
            bodyMarkdown: "패치, 구성 변경, 권한 축소, 탐지 규칙을 제안하고 동일한 검증 절차를 다시 수행해 취약 조건이 제거되었는지 확인합니다.",
          },
        ],
  };
}

function buildQuestions(
  team: TeamType,
  questionTypes: QuestionType[],
  techniques: string[],
  telemetryEvents: JsonObject[],
  blueProfile: BlueScenarioProfile | null,
  redProfile: RedScenarioProfile | null,
): { publicQuestions: JsonObject[]; gradingQuestions: JsonObject[] } {
  if (team === "blue") {
    const evidenceIds = telemetryEvents.map((event) => String(event.id));
    const definitions: Array<{ id: string; type: QuestionType; prompt: string; points: number; answerKey: JsonObject }> = [
      {
        id: "blue-elk-entry",
        type: "elk_search",
        prompt: "정상 운영 로그와 구분되는 최초 침해 징후를 찾으세요. 인증 또는 외부 노출 지점의 이벤트를 시간순으로 비교하고, 최초 진입 정황을 직접 뒷받침하는 증거를 선택한 뒤 사용한 KQL을 제출하세요.",
        points: 20,
        answerKey: { expectedEvidenceIds: evidenceIds.slice(0, 2) },
      },
      {
        id: "blue-elk-execution",
        type: "elk_search",
        prompt: `최초 침해 이후 ${blueProfile?.executionLabel ?? "후속 실행"} 흐름을 재구성하세요. 동일한 사용자·호스트·프로세스 계보를 연결해 실행 단계와 후속 행위를 입증하는 증거를 선택하세요.`,
        points: 20,
        answerKey: { expectedEvidenceIds: evidenceIds.slice(1, 3) },
      },
      {
        id: "blue-elk-exfiltration",
        type: "elk_search",
        prompt: `${blueProfile?.impactLabel ?? "최종 영향"} 단계의 타임라인을 완성하세요. 앞선 실행 흐름과 같은 사용자 또는 호스트에서 이어진 사건임을 보여주는 증거를 모두 선택하고 검색 쿼리를 제출하세요.`,
        points: 20,
        answerKey: { expectedEvidenceIds: evidenceIds.slice(3, 6) },
      },
      {
        id: "blue-mitre-entry",
        type: "mitre_attack",
        prompt: "최초 침해 단계에서 관찰된 인증 또는 접근 행위를 가장 잘 설명하는 MITRE ATT&CK 기법을 후보 목록에서 선택하세요. 도구명이 아닌 인증 맥락과 접근 목적을 기준으로 판단하세요.",
        points: 15,
        answerKey: { techniqueIds: [techniques[0]] },
      },
      {
        id: "blue-mitre-execution",
        type: "mitre_attack",
        prompt: `${blueProfile?.executionLabel ?? "실행 및 후속 행위"}를 설명하는 MITRE ATT&CK 기법을 선택하세요. 프로세스 계보와 행위의 목적을 함께 고려하세요.`,
        points: 15,
        answerKey: { techniqueIds: [techniques[1] ?? techniques[0]] },
      },
      {
        id: "blue-mitre-chain",
        type: "mitre_attack",
        prompt: "전체 공격 타임라인을 구성하는 핵심 MITRE ATT&CK 기법을 모두 선택하세요. 최초 접근과 명령 실행처럼 서로 다른 단계가 포함되어야 하며, ELK에서 확인한 증거 흐름을 기준으로 선택하세요.",
        points: 10,
        answerKey: { techniqueIds: techniques.slice(0, Math.min(3, techniques.length)) },
      },
    ];
    return projectQuestions(definitions);
  }

  return buildRedQuestions(questionTypes, techniques, redProfile!);

  /* c8 ignore start -- retained only for older serialized fixture readability */
  const definitions = questionTypes.map((type, index) => {
    const id = `red-q${index + 1}`;
    const base = { id, type, points: type === "mitre_attack" ? 20 : 30 };
    if (type === "single_choice") return {
      ...base,
      prompt: "격리된 대상의 공격 표면을 확인한 뒤 다음 단계로 가장 적절한 검증 행동을 선택하세요. 범위 통제와 증거 보존을 함께 고려해야 합니다.",
      options: [
        { id: "bounded-enumeration", label: "허용된 대상과 포트 범위에서 서비스와 버전을 식별한다." },
        { id: "disable-audit", label: "탐지를 피하기 위해 대상의 감사 로그를 비활성화한다." },
        { id: "external-scan", label: "유사 시스템을 찾기 위해 인터넷 대역으로 스캔 범위를 확장한다." },
        { id: "destructive-test", label: "영향 확인을 위해 데이터 삭제 동작부터 실행한다." },
      ],
      answerKey: { optionIds: ["bounded-enumeration"] },
    };
    if (type === "multiple_choice") return {
      ...base,
      prompt: "시뮬레이션 공격 흐름을 입증하면서 방어팀의 탐지 규칙 개선에도 직접 활용할 수 있는 관측 증거를 모두 선택하세요.",
      options: [
        { id: "process-lineage", label: "부모·자식 프로세스 관계와 명령행" },
        { id: "auth-context", label: "인증 주체, 출발지, 성공 여부가 포함된 이벤트" },
        { id: "network-flow", label: "대상 서비스와 연계된 네트워크 연결 기록" },
        { id: "marketing-cookie", label: "공격 흐름과 무관한 마케팅 쿠키" },
      ],
      answerKey: { optionIds: ["process-lineage", "auth-context", "network-flow"] },
    };
    if (type === "mitre_attack") return {
      ...base,
      prompt: "격리 환경에서 실제로 관찰한 공격 행위를 가장 잘 설명하는 MITRE ATT&CK 기법을 선택하세요. 사용 도구가 아니라 행위의 목적과 대상에 근거해야 합니다.",
      answerKey: { techniqueIds: [techniques[index % techniques.length]] },
    };
    return {
      ...base,
      prompt: "발견한 공격 경로를 초기 조건, 실행 단계, 영향, 방어 관측 지점 순서로 설명하고 이를 차단할 완화 조치와 재검증 방법을 근거와 함께 작성하세요.",
      answerKey: { rubricId: `${id}-analysis-rubric-v2` },
    };
  });
  return projectQuestions(definitions);
  /* c8 ignore stop */
}

function projectQuestions(
  definitions: Array<JsonObject & { answerKey: JsonObject }>,
): { publicQuestions: JsonObject[]; gradingQuestions: JsonObject[] } {
  return {
    publicQuestions: definitions.map(({ answerKey: _answerKey, ...question }) => question),
    gradingQuestions: definitions.map(({ answerKey, ...question }) => ({ ...question, answerKey })),
  };
}

function buildRedLearning(input: {
  title: string;
  prompt: string;
  profile: RedScenarioProfile;
  cveIds: string[];
}): JsonObject {
  const cveContext = input.cveIds.length > 0
    ? `\n\n학습 대상 식별자: **${input.cveIds.join(", ")}**. 식별자만으로 제품·버전·공격 조건을 단정하지 말고, 제공된 대상의 배너와 동작을 기준으로 적용 가능성을 확인합니다.`
    : "";
  return {
    title: input.title,
    summary: input.profile.summary,
    prerequisites: [
      "TCP/IP, HTTP 및 Linux 기본 사용법",
      "서비스 식별과 취약점 적용 조건의 기초",
      "격리 환경의 범위 통제와 증거 보존 원칙",
    ],
    objectives: [
      `${input.profile.surfaceLabel}의 공격 표면과 신뢰할 수 있는 서비스 특성을 식별합니다.`,
      `${input.profile.validationFocus}에 필요한 전제 조건을 확인하고 비파괴 방식으로 재현 가능성을 평가합니다.`,
      `검증 과정에서 남는 ${input.profile.defenderSignals}을 방어 관점의 관측 지점으로 설명합니다.`,
      "관찰한 행위를 MITRE ATT&CK 후보와 연결하고 완화 후 동일 절차로 재검증합니다.",
    ],
    sections: [
      {
        id: "scenario-scope",
        title: "시나리오 브리핑과 허용 범위",
        bodyMarkdown: `## ${input.title}\n\n${input.prompt}${cveContext}\n\n${input.profile.summary}\n\n모든 활동은 제공된 Kali 환경과 격리된 대상에 한정합니다. 외부 주소 탐색, 지속성 확보, 로그 훼손 및 서비스 가용성을 해치는 동작은 허용되지 않습니다.`,
      },
      {
        id: "vulnerability-model",
        title: "취약 조건과 검증 가설",
        bodyMarkdown: `${input.profile.surfaceLabel}에서 ${input.profile.validationFocus}을 검증합니다. 먼저 노출 서비스, 버전 또는 기능, 인증 상태, 입력 경로와 같은 전제 조건을 표로 정리하세요. 공개 CVE가 지정된 경우에도 식별자 일치만으로 취약하다고 결론 내리지 말고 대상에서 확인한 사실과 아직 확인되지 않은 가정을 분리합니다.`,
      },
      {
        id: "recon-validation-workflow",
        title: "정찰과 비파괴 검증 워크플로",
        bodyMarkdown: "1. 허용된 대상과 포트 범위를 확인합니다.\n2. 서비스 배너와 정상 응답 기준선을 기록합니다.\n3. 취약 조건을 한 번에 하나씩 확인하고 요청·응답 차이를 보존합니다.\n4. 영향 검증은 제공된 표식 파일이나 제한 계정처럼 복구 가능한 자원만 사용합니다.\n5. 성공과 실패를 모두 기록하고 다른 원인으로 설명 가능한지 반증합니다.",
      },
      {
        id: "attack-chain-evidence",
        title: "공격 경로와 증거 기록",
        bodyMarkdown: `초기 표면 확인부터 제한된 영향 검증까지 각 단계에 입력, 관찰 결과, 판단 근거를 남깁니다. 특히 ${input.profile.defenderSignals}을 함께 수집하면 공격 성공 여부뿐 아니라 탐지 가능한 경계를 설명할 수 있습니다. 명령이나 도구 이름만 나열하지 말고 어떤 조건을 검증했고 어떤 상태 변화가 관찰되었는지 기술하세요.`,
      },
      {
        id: "mitre-defender-context",
        title: "MITRE ATT&CK와 방어 관측 지점",
        bodyMarkdown: "ATT&CK 매핑은 사용 도구가 아니라 행위의 목적, 대상, 결과를 기준으로 수행합니다. 표면 탐색, 취약 조건 악용, 명령 실행, 정보 접근처럼 서로 다른 단계의 후보를 비교하고 방어자가 어느 로그와 네트워크 지점에서 이를 관찰할 수 있는지 연결하세요. 강의 자료에는 문제의 정확한 기법 ID나 정답 조합을 제공하지 않습니다.",
      },
      {
        id: "remediation-retest",
        title: "완화 조치와 재검증",
        bodyMarkdown: `${input.profile.mitigationFocus}을 우선 검토합니다. 패치 또는 구성 변경 전후에 동일한 안전 검증 절차를 수행하고, 취약 조건이 제거되었는지와 정상 기능이 유지되는지를 함께 확인하세요. 최종 보고서에는 영향 범위, 방어 관측 지점, 잔여 위험과 추가 모니터링 권고를 포함합니다.`,
      },
    ],
  };
}

function buildRedQuestions(
  questionTypes: QuestionType[],
  techniques: string[],
  profile: RedScenarioProfile,
): { publicQuestions: JsonObject[]; gradingQuestions: JsonObject[] } {
  const expandedTypes = [...questionTypes];
  while (expandedTypes.length < 4) {
    expandedTypes.push(questionTypes[expandedTypes.length % questionTypes.length]!);
  }
  const seen = new Map<QuestionType, number>();
  const definitions = expandedTypes.map((type, index) => {
    const variant = (seen.get(type) ?? 0) + 1;
    seen.set(type, variant);
    const id = `red-q${index + 1}`;
    const base = { id, type, points: type === "mitre_attack" ? 20 : 30 };
    if (type === "single_choice") {
      if (variant === 1) {
        return {
          ...base,
          prompt: `${profile.surfaceLabel}의 취약 가능성을 처음 확인했습니다. 범위를 지키면서 다음 검증 단계의 신뢰도를 가장 높이는 행동을 하나 선택하세요. 서비스 특성, 취약 전제 조건과 증거 보존을 함께 고려해야 합니다.`,
          options: [
            { id: "bounded-enumeration", label: `허용된 대상과 포트 안에서 ${profile.surfaceLabel}의 서비스·버전·정상 응답 기준선을 기록한다.` },
            { id: "disable-audit", label: "행위가 탐지되지 않도록 대상의 감사 로그를 비활성화한다." },
            { id: "external-scan", label: "유사 대상을 찾기 위해 인터넷 주소 대역으로 탐색 범위를 확장한다." },
            { id: "destructive-test", label: "영향을 빠르게 확인하기 위해 데이터 삭제나 서비스 중단부터 수행한다." },
          ],
          answerKey: { optionIds: ["bounded-enumeration"] },
        };
      }
      return {
        ...base,
        prompt: `대상이 ${profile.validationFocus} 조건을 만족한다고 결론 내리기 전에 반드시 확인해야 할 근거로 가장 적절한 것을 하나 선택하세요.`,
        options: [
          { id: "verified-preconditions", label: "대상에서 확인한 제품·버전·기능 상태와 안전 검증의 요청·응답 차이" },
          { id: "cve-id-only", label: "프롬프트에 CVE 식별자가 포함되었다는 사실만으로 취약함을 확정" },
          { id: "tool-banner-only", label: "자동화 도구가 출력한 위험 등급만 보존하고 원본 증거는 제외" },
          { id: "unrelated-host", label: "범위 밖의 다른 호스트에서 재현된 결과를 현재 대상의 근거로 대체" },
        ],
        answerKey: { optionIds: ["verified-preconditions"] },
      };
    }
    if (type === "multiple_choice") {
      if (variant === 1) {
        return {
          ...base,
          prompt: `${profile.validationFocus} 흐름을 입증하고 방어팀의 탐지 개선에도 사용할 수 있는 증거를 모두 선택하세요. 서로 다른 관측 계층을 연결해야 합니다.`,
          options: [
            { id: "process-lineage", label: `검증 전후 ${profile.defenderSignals}에서 확인한 프로세스 또는 서비스 실행 관계` },
            { id: "auth-context", label: "인증 주체, 출발지, 성공·실패와 권한 상태가 포함된 기록" },
            { id: "network-flow", label: "대상 서비스와 검증 워크스테이션 사이의 시간대가 일치하는 네트워크 흐름" },
            { id: "marketing-cookie", label: "공격 경로 및 취약 조건과 관계없는 마케팅 분석 쿠키" },
          ],
          answerKey: { optionIds: ["process-lineage", "auth-context", "network-flow"] },
        };
      }
      return {
        ...base,
        prompt: "재현 가능한 취약점 보고서에 포함해야 할 항목을 모두 선택하세요. 추측과 관찰 사실을 구분해야 합니다.",
        options: [
          { id: "target-fingerprint", label: "대상 서비스의 식별 정보와 검증 시점" },
          { id: "preconditions", label: "취약 동작이 나타나는 인증·기능·입력 전제 조건" },
          { id: "defender-evidence", label: `검증 과정에서 남은 ${profile.defenderSignals}과 타임라인` },
          { id: "secret-material", label: "보고서 재현성을 위해 실제 비밀번호와 토큰 원문을 첨부" },
        ],
        answerKey: { optionIds: ["target-fingerprint", "preconditions", "defender-evidence"] },
      };
    }
    if (type === "mitre_attack") {
      const executionTechnique = techniques[1] ?? techniques[0]!;
      return {
        ...base,
        prompt: variant === 1
          ? `${profile.validationFocus} 과정에서 관찰한 핵심 실행 또는 접근 행위를 가장 잘 설명하는 MITRE ATT&CK 기법을 선택하세요. 도구 이름이 아닌 행위의 목적과 대상에 근거해야 합니다.`
          : "초기 표면 확인부터 제한된 영향 검증까지의 공격 경로를 설명하는 MITRE ATT&CK 기법을 모두 선택하세요. 서로 다른 전술 단계의 관찰 증거를 기준으로 판단하세요.",
        answerKey: {
          techniqueIds: variant === 1
            ? [executionTechnique]
            : techniques.slice(0, Math.min(3, techniques.length)),
        },
      };
    }
    return {
      ...base,
      prompt: variant === 1
        ? `${profile.surfaceLabel}에서 확인한 공격 경로를 전제 조건, 안전 검증, 관찰된 영향, ${profile.defenderSignals}, 완화 조치 순서로 설명하세요. 사실과 가정을 구분하고 ${profile.mitigationFocus} 이후의 재검증 방법도 제시해야 합니다.`
        : "현재 결과를 취약점 악용이 아닌 정상 동작이나 구성 오류로 설명할 수 있는 대안 가설을 제시하고, 두 가설을 구분할 추가 증거와 안전한 재검증 절차를 작성하세요.",
      answerKey: { rubricId: `${id}-analysis-rubric-v3` },
    };
  });
  return projectQuestions(definitions);
}

const RED_TECHNIQUES: Readonly<Record<string, { name: string; tactic: string }>> = {
  T1005: { name: "Data from Local System", tactic: "collection" },
  "T1021.004": { name: "SSH", tactic: "lateral-movement" },
  T1046: { name: "Network Service Discovery", tactic: "discovery" },
  "T1059.004": { name: "Unix Shell", tactic: "execution" },
  "T1074.001": { name: "Local Data Staging", tactic: "collection" },
  T1078: { name: "Valid Accounts", tactic: "initial-access" },
  T1082: { name: "System Information Discovery", tactic: "discovery" },
  T1083: { name: "File and Directory Discovery", tactic: "discovery" },
  T1110: { name: "Brute Force", tactic: "credential-access" },
  T1190: { name: "Exploit Public-Facing Application", tactic: "initial-access" },
  "T1505.003": { name: "Web Shell", tactic: "persistence" },
  "T1595.002": { name: "Vulnerability Scanning", tactic: "reconnaissance" },
  T1610: { name: "Deploy Container", tactic: "defense-evasion" },
  T1611: { name: "Escape to Host", tactic: "privilege-escalation" },
};

function mergeRequestedTechniques(
  requested: string[],
  profileChain: RedScenarioProfile["attackChain"],
): RedScenarioProfile["attackChain"] {
  const profileById = new Map(profileChain.map((item) => [item.id, item]));
  const result: RedScenarioProfile["attackChain"] = [];
  for (const rawId of requested) {
    const id = rawId.toUpperCase();
    if (result.some((item) => item.id === id)) continue;
    const known = profileById.get(id) ?? RED_TECHNIQUES[id];
    result.push({
      id,
      name: known?.name ?? `ATT&CK ${id}`,
      tactic: known?.tactic ?? "execution",
    });
  }
  for (const item of profileChain) {
    if (!result.some((candidate) => candidate.id === item.id)) result.push(item);
  }
  return result.slice(0, 6);
}

function selectRedProfile(value: string): RedScenarioProfile {
  if (/(container|docker|kubernetes|k8s|escape|컨테이너|도커|쿠버네티스|호스트\s*탈출)/i.test(value)) {
    return {
      id: "container_escape",
      summary: "격리된 컨테이너 서비스의 노출 구성과 런타임 경계를 확인하고, 제한된 권한 검증으로 호스트 영향 가능성과 방어 관측 지점을 평가하는 레드팀 시나리오입니다.",
      logSources: ["container.runtime", "kubernetes.audit", "linux.audit", "process", "firewall"],
      attackChain: [
        { id: "T1610", name: "Deploy Container", tactic: "defense-evasion" },
        { id: "T1611", name: "Escape to Host", tactic: "privilege-escalation" },
        { id: "T1059.004", name: "Unix Shell", tactic: "execution" },
        { id: "T1082", name: "System Information Discovery", tactic: "discovery" },
      ],
      surfaceLabel: "컨테이너 런타임과 오케스트레이션 경계",
      validationFocus: "과도한 권한, 위험한 마운트 및 런타임 격리 실패 가능성",
      defenderSignals: "컨테이너 생성·권한 변경·프로세스·감사 로그",
      mitigationFocus: "최소 권한 보안 컨텍스트, 위험한 마운트 제거와 런타임 정책 강화",
    };
  }
  if (/(credential|password|brute.?force|valid account|ssh|login|계정|자격\s*증명|비밀번호|무차별\s*대입|로그인|인증)/i.test(value)) {
    return {
      id: "credential_access",
      summary: "노출된 원격 접근 서비스에서 인증 정책과 계정 보호 상태를 확인하고, 제한된 자격 증명 검증을 통해 계정 악용 가능성과 방어 탐지 지점을 평가하는 레드팀 시나리오입니다.",
      logSources: ["authentication", "linux.audit", "sshd", "pam", "firewall"],
      attackChain: [
        { id: "T1046", name: "Network Service Discovery", tactic: "discovery" },
        { id: "T1110", name: "Brute Force", tactic: "credential-access" },
        { id: "T1078", name: "Valid Accounts", tactic: "initial-access" },
        { id: "T1021.004", name: "SSH", tactic: "lateral-movement" },
      ],
      surfaceLabel: "원격 인증 및 계정 접근 서비스",
      validationFocus: "인증 정책, 계정 잠금, 제한 계정의 접근 범위",
      defenderSignals: "인증 성공·실패, 세션, 권한 변경 및 원격 접속 로그",
      mitigationFocus: "다중 인증, 계정 잠금, 비밀번호 정책과 원격 접근 허용 목록",
    };
  }
  if (/(path.?traversal|directory.?traversal|file.?read|lfi|upload|download|경로\s*조작|디렉터리\s*순회|파일\s*읽기|파일\s*업로드|파일\s*다운로드)/i.test(value)) {
    return {
      id: "file_exposure",
      summary: "웹 애플리케이션의 파일 처리 기능과 경로 검증 경계를 확인하고, 제공된 표식 파일만 사용해 비인가 파일 접근 또는 저장 가능성과 관측 증거를 평가하는 레드팀 시나리오입니다.",
      logSources: ["waf", "web.access", "application", "file_integrity", "linux.audit"],
      attackChain: [
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
        { id: "T1083", name: "File and Directory Discovery", tactic: "discovery" },
        { id: "T1005", name: "Data from Local System", tactic: "collection" },
        { id: "T1074.001", name: "Local Data Staging", tactic: "collection" },
      ],
      surfaceLabel: "웹 파일 처리와 경로 검증 기능",
      validationFocus: "경로 정규화, 파일 형식·권한 검사 및 비인가 파일 접근 가능성",
      defenderSignals: "웹 요청·응답, 애플리케이션 오류, 파일 접근 및 무결성 로그",
      mitigationFocus: "허용 목록 기반 경로 검증, 저장소 격리와 서비스 계정 권한 축소",
    };
  }
  if (/(web|http|api|rce|sqli|sql\s*injection|ssrf|deserial|log4j|spring|struts|tomcat|wordpress|php|웹|원격\s*코드|코드\s*실행|인젝션|역직렬화)/i.test(value)) {
    return {
      id: "web_application",
      summary: "격리된 웹 애플리케이션의 노출 기능과 입력 처리 경계를 식별하고, 비파괴 검증으로 서버 측 영향 가능성과 방어 관측 지점을 평가하는 레드팀 시나리오입니다.",
      logSources: ["waf", "web.access", "application", "linux.audit", "process", "firewall"],
      attackChain: [
        { id: "T1595.002", name: "Vulnerability Scanning", tactic: "reconnaissance" },
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
        { id: "T1059.004", name: "Unix Shell", tactic: "execution" },
        { id: "T1083", name: "File and Directory Discovery", tactic: "discovery" },
      ],
      surfaceLabel: "공개 웹 애플리케이션과 API 입력 경계",
      validationFocus: "노출 기능, 입력 처리와 서버 측 동작의 취약 조건",
      defenderSignals: "WAF·웹 접근·애플리케이션·프로세스·네트워크 로그",
      mitigationFocus: "영향 버전 패치, 입력 검증, 서비스 계정 최소 권한과 실행 통제",
    };
  }
  return {
    id: "generic_validation",
    summary: "프롬프트에 제시된 격리 대상을 먼저 식별하고, 확인된 서비스와 기능에만 근거한 비파괴 검증으로 취약 조건과 방어 관측 지점을 평가하는 일반 레드팀 시나리오입니다.",
    logSources: ["network", "service", "authentication", "linux.audit", "firewall"],
    attackChain: [
      { id: "T1595.002", name: "Vulnerability Scanning", tactic: "reconnaissance" },
      { id: "T1046", name: "Network Service Discovery", tactic: "discovery" },
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
      { id: "T1059.004", name: "Unix Shell", tactic: "execution" },
    ],
    surfaceLabel: "프롬프트로 지정된 격리 대상의 서비스 표면",
    validationFocus: "대상에서 실제로 확인된 제품·버전·기능과 취약 전제 조건",
    defenderSignals: "서비스 요청, 인증, 프로세스, 감사 및 네트워크 로그",
    mitigationFocus: "확인된 영향 조건에 맞는 패치·구성 변경과 최소 권한 적용",
  };
}

function selectBlueProfile(value: string): BlueScenarioProfile {
  if (/(ransomware|랜섬|암호화|encrypt|shadow copy|복구\s*방해)/i.test(value)) {
    return {
      id: "ransomware",
      summary: "초기 계정 접근 이후 복구 기능 방해와 대량 파일 암호화로 이어지는 랜섬웨어 행위를 엔드포인트·인증·파일 로그로 추적하는 시나리오입니다.",
      logSources: ["windows.security", "windows.sysmon", "powershell", "edr", "file_integrity", "firewall"],
      attackChain: [
        { id: "T1078", name: "Valid Accounts", tactic: "initial-access" },
        { id: "T1059.001", name: "PowerShell", tactic: "execution" },
        { id: "T1490", name: "Inhibit System Recovery", tactic: "impact" },
        { id: "T1486", name: "Data Encrypted for Impact", tactic: "impact" },
      ],
      executionLabel: "복구 방해 명령과 프로세스 실행",
      impactLabel: "대량 파일 암호화 및 복구 방해",
    };
  }
  if (/(credential|identity|impossible\s*travel|valid account|아이덴티티|계정|인증\s*이상|로그인\s*이상|brute.?force|무차별\s*대입)/i.test(value)) {
    return {
      id: "credential_abuse",
      summary: "반복된 인증 실패 이후 성공한 비정상 로그인과 권한·원격접속 변화를 연계해 계정 탈취 및 악용 범위를 조사하는 시나리오입니다.",
      logSources: ["windows.security", "authentication", "vpn", "edr", "active_directory", "firewall"],
      attackChain: [
        { id: "T1110", name: "Brute Force", tactic: "credential-access" },
        { id: "T1078", name: "Valid Accounts", tactic: "initial-access" },
        { id: "T1098", name: "Account Manipulation", tactic: "persistence" },
        { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "lateral-movement" },
      ],
      executionLabel: "비정상 계정 사용과 권한 변경",
      impactLabel: "원격접속 및 내부 자원 접근 확대",
    };
  }
  if (/(web\s*shell|webshell|웹\s*셸|웹쉘)/i.test(value)) {
    return {
      id: "webshell",
      summary: "공개 웹 서비스 악용 이후 웹셸 파일 생성과 서버 명령 실행, 추가 도구 전송으로 이어지는 침해 흐름을 조사하는 시나리오입니다.",
      logSources: ["waf", "web.access", "linux.audit", "process", "file_integrity", "firewall"],
      attackChain: [
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
        { id: "T1505.003", name: "Web Shell", tactic: "persistence" },
        { id: "T1059.004", name: "Unix Shell", tactic: "execution" },
        { id: "T1105", name: "Ingress Tool Transfer", tactic: "command-and-control" },
      ],
      executionLabel: "웹셸 기반 명령 실행",
      impactLabel: "추가 도구 반입과 외부 통신",
    };
  }
  // Do not force every web RCE or CVE-only request into the Windows/PowerShell
  // storyline. That profile is valid only when PowerShell is an explicit part
  // of the requested scenario; other RCEs retain the prompt/CVE-backed generic
  // signal set (or are generated dynamically by the production AI path).
  if (/(powershell|power\s*shell|파워쉘|파워셸)/i.test(value)) {
    return {
      id: "powershell_rce_exfiltration",
      summary: "웹 서비스의 원격 코드 실행 가능성이 악용된 뒤 PowerShell 실행, 민감정보 수집·압축과 외부 반출로 이어지는 침해 흐름을 조사하는 시나리오입니다.",
      logSources: ["waf", "web.access", "windows.sysmon", "powershell", "file_integrity", "firewall", "dns"],
      attackChain: [
        { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
        { id: "T1059.001", name: "PowerShell", tactic: "execution" },
        { id: "T1005", name: "Data from Local System", tactic: "collection" },
        { id: "T1560.001", name: "Archive via Utility", tactic: "collection" },
        { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "exfiltration" },
      ],
      executionLabel: "PowerShell 실행과 시스템 정찰",
      impactLabel: "민감정보 수집·압축 및 외부 반출",
    };
  }
  return {
    id: "generic_intrusion",
    summary: "공개 서비스의 이상 요청 이후 명령 실행, 파일 탐색, 외부 통신으로 이어지는 일반 침해 흐름을 다중 로그로 재구성하는 시나리오입니다.",
    logSources: ["waf", "web.access", "process", "linux.audit", "file_integrity", "firewall", "dns"],
    attackChain: [
      { id: "T1190", name: "Exploit Public-Facing Application", tactic: "initial-access" },
      { id: "T1059.004", name: "Unix Shell", tactic: "execution" },
      { id: "T1083", name: "File and Directory Discovery", tactic: "discovery" },
      { id: "T1071.001", name: "Web Protocols", tactic: "command-and-control" },
    ],
    executionLabel: "명령 실행과 파일 탐색",
    impactLabel: "외부 통신 및 후속 접근",
  };
}

function blueSignalEvents(now: Date, profile: BlueScenarioProfile): JsonObject[] {
  const timestamp = (minutesBefore: number) =>
    new Date(now.getTime() - minutesBefore * 60_000).toISOString();
  const common = { host: { name: "host-01" }, user: { name: "scenario_user" } };
  const definitions: Array<{ id: string; minutes: number; message: string; category: string; technique: number; fields: JsonObject }> =
    profile.id === "powershell_rce_exfiltration"
      ? [
          { id: "signal-web-rce-probe", minutes: 18, message: "비정상 웹 요청 직후 서비스 프로세스의 실행 흐름이 달라졌습니다.", category: "web", technique: 0, fields: { host: { name: "web-01" }, source: { ip: "192.0.2.44" }, url: { path: "/api/export" } } },
          { id: "signal-webshell-powershell", minutes: 16, message: "웹 서비스 프로세스에서 PowerShell 자식 프로세스가 생성되었습니다.", category: "process", technique: 1, fields: { host: { name: "web-01" }, user: { name: "svc_web" }, process: { name: "powershell.exe", parent: { name: "w3wp.exe" }, entity_id: "proc-ps-001" } } },
          { id: "signal-powershell-recon", minutes: 14, message: "PowerShell 프로세스가 시스템과 데이터 위치를 탐색했습니다.", category: "process", technique: 1, fields: { host: { name: "web-01" }, user: { name: "svc_web" }, process: { name: "powershell.exe", entity_id: "proc-ps-001" } } },
          { id: "signal-sensitive-file-read", minutes: 11, message: "서비스 계정이 평소 접근하지 않던 민감 데이터 파일을 읽었습니다.", category: "file", technique: 2, fields: { host: { name: "web-01" }, user: { name: "svc_web" }, file: { path: "C:\\Data\\customer-export.csv" } } },
          { id: "signal-archive-created", minutes: 8, message: "민감 데이터 디렉터리에서 새 압축 파일이 생성되었습니다.", category: "file", technique: 3, fields: { host: { name: "web-01" }, user: { name: "svc_web" }, file: { path: "C:\\ProgramData\\cache\\export.zip" } } },
          { id: "signal-outbound-exfiltration", minutes: 5, message: "침해 호스트에서 드문 외부 목적지로 대용량 연결이 발생했습니다.", category: "network", technique: 4, fields: { host: { name: "web-01" }, source: { ip: "10.20.30.15", bytes: 18_642_771 }, destination: { ip: "198.51.100.77", port: 443 }, network: { direction: "egress", transport: "tcp" } } },
        ]
      : profile.id === "credential_abuse"
        ? [
            { id: "signal-auth-failure-burst", minutes: 22, message: "단일 출발지에서 여러 계정으로 인증 실패가 급증했습니다.", category: "authentication", technique: 0, fields: { source: { ip: "192.0.2.91" }, event: { outcome: "failure" } } },
            { id: "signal-auth-success-anomaly", minutes: 18, message: "실패 급증 직후 평소와 다른 위치에서 인증이 성공했습니다.", category: "authentication", technique: 1, fields: { source: { ip: "192.0.2.91" }, event: { outcome: "success" }, user: { name: "ops_admin" } } },
            { id: "signal-privileged-group-change", minutes: 14, message: "인증된 계정이 권한 그룹 구성원을 변경했습니다.", category: "iam", technique: 2, fields: { user: { name: "ops_admin" }, group: { name: "Remote Management Users" } } },
            { id: "signal-remote-session-created", minutes: 11, message: "권한 변경 이후 새 원격 데스크톱 세션이 생성되었습니다.", category: "session", technique: 3, fields: { source: { ip: "10.20.40.31" }, destination: { ip: "10.20.40.18", port: 3389 } } },
            { id: "signal-remote-process-start", minutes: 8, message: "원격 세션에서 관리 도구 프로세스가 시작되었습니다.", category: "process", technique: 3, fields: { process: { name: "mmc.exe", entity_id: "proc-remote-001" } } },
            { id: "signal-privileged-resource-access", minutes: 5, message: "새 원격 세션이 민감 관리 공유에 접근했습니다.", category: "file", technique: 1, fields: { file: { path: "\\\\filesrv\\admin$\\policy" } } },
          ]
        : profile.id === "ransomware"
          ? [
              { id: "signal-ransom-auth", minutes: 20, message: "평소와 다른 위치에서 관리 계정 로그인이 성공했습니다.", category: "authentication", technique: 0, fields: { source: { ip: "192.0.2.61" }, event: { outcome: "success" } } },
              { id: "signal-ransom-powershell", minutes: 17, message: "관리 계정으로 PowerShell 프로세스가 실행되었습니다.", category: "process", technique: 1, fields: { process: { name: "powershell.exe", entity_id: "proc-ransom-001" } } },
              { id: "signal-recovery-inhibited", minutes: 13, message: "시스템 복구 기능과 백업 카탈로그 변경이 감지되었습니다.", category: "process", technique: 2, fields: { process: { name: "vssadmin.exe", parent: { name: "powershell.exe" } } } },
              { id: "signal-file-enumeration", minutes: 10, message: "사용자 문서 경로의 파일 열람이 급증했습니다.", category: "file", technique: 3, fields: { file: { directory: "C:\\Users\\Public\\Documents" } } },
              { id: "signal-mass-file-rewrite", minutes: 7, message: "짧은 시간에 다수 파일의 내용과 확장자가 변경되었습니다.", category: "file", technique: 3, fields: { file: { extension: "locked" }, event: { action: "file-modified" } } },
              { id: "signal-ransom-note", minutes: 4, message: "여러 디렉터리에 동일한 안내 파일이 생성되었습니다.", category: "file", technique: 3, fields: { file: { name: "RECOVER_FILES.txt" } } },
            ]
          : profile.id === "webshell"
            ? [
                { id: "signal-web-exploit", minutes: 19, message: "공개 웹 경로에 비정상 요청 패턴이 관찰되었습니다.", category: "web", technique: 0, fields: { source: { ip: "192.0.2.73" }, url: { path: "/upload" } } },
                { id: "signal-webshell-file", minutes: 16, message: "웹 루트 하위에 새 스크립트 파일이 생성되었습니다.", category: "file", technique: 1, fields: { file: { path: "/var/www/html/assets/cache.php" } } },
                { id: "signal-webshell-command", minutes: 13, message: "웹 서버 계정으로 셸 프로세스가 시작되었습니다.", category: "process", technique: 2, fields: { process: { name: "sh", parent: { name: "php-fpm" }, entity_id: "proc-shell-001" } } },
                { id: "signal-tool-download", minutes: 10, message: "웹 서버에서 새 실행 파일 다운로드가 관찰되었습니다.", category: "network", technique: 3, fields: { destination: { ip: "198.51.100.42", port: 443 } } },
                { id: "signal-tool-permission-change", minutes: 7, message: "다운로드한 파일의 실행 권한이 변경되었습니다.", category: "file", technique: 3, fields: { file: { path: "/tmp/.cache/tool" }, event: { action: "chmod" } } },
                { id: "signal-webshell-callback", minutes: 4, message: "웹 서버에서 드문 외부 목적지로 주기적 통신이 발생했습니다.", category: "network", technique: 3, fields: { destination: { ip: "198.51.100.42", port: 443 } } },
              ]
            : [
                { id: "signal-generic-entry", minutes: 18, message: "외부 노출 서비스에 비정상 요청이 관찰되었습니다.", category: "web", technique: 0, fields: { source: { ip: "192.0.2.88" } } },
                { id: "signal-generic-shell", minutes: 15, message: "서비스 계정으로 셸 프로세스가 실행되었습니다.", category: "process", technique: 1, fields: { process: { name: "sh", entity_id: "proc-generic-001" } } },
                { id: "signal-generic-discovery", minutes: 12, message: "셸 프로세스가 파일과 디렉터리 목록을 열람했습니다.", category: "process", technique: 2, fields: { process: { name: "find", parent: { entity_id: "proc-generic-001" } } } },
                { id: "signal-generic-file-access", minutes: 9, message: "서비스 계정이 구성 파일을 열람했습니다.", category: "file", technique: 2, fields: { file: { path: "/opt/app/config/settings.yml" } } },
                { id: "signal-generic-dns", minutes: 6, message: "호스트에서 드문 도메인 조회가 발생했습니다.", category: "network", technique: 3, fields: { dns: { question: { name: "updates.example.invalid" } } } },
                { id: "signal-generic-egress", minutes: 3, message: "서비스 호스트에서 새 외부 목적지로 HTTPS 통신이 발생했습니다.", category: "network", technique: 3, fields: { destination: { ip: "198.51.100.55", port: 443 } } },
              ];
  return definitions.map((definition) => ({
    id: definition.id,
    document: {
      "@timestamp": timestamp(definition.minutes),
      message: definition.message,
      ...common,
      ...definition.fields,
      event: {
        ...(typeof definition.fields.event === "object" && definition.fields.event !== null
          ? definition.fields.event as JsonObject
          : {}),
        id: definition.id,
        kind: "alert",
        category: definition.category,
        dataset: `zerotop.${profile.id}`,
      },
      threat: {
        framework: "MITRE ATT&CK",
        technique: { id: [profile.attackChain[definition.technique]?.id ?? profile.attackChain[0]!.id] },
      },
    },
  }));
}
