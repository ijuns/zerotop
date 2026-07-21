"use client";

import { useMemo, useState } from "react";

export interface MitreTechniqueOption {
  id: string;
  name?: string;
  tactic?: string;
}

interface MitreTechniqueSelectorProps {
  team: "blue" | "red";
  techniques: MitreTechniqueOption[];
  selected: string[];
  disabled?: boolean;
  onChange: (techniqueIds: string[]) => void;
}

interface CatalogTechnique {
  id: string;
  name: string;
  tactic: string;
  contextual?: boolean;
}

const TACTICS = [
  "초기 침투",
  "실행",
  "지속성",
  "권한 상승",
  "방어 회피",
  "자격 증명 접근",
  "탐색",
  "측면 이동",
  "수집",
  "명령 및 제어",
  "유출",
  "영향",
  "기타",
] as const;

const TACTIC_ALIASES: Record<string, string> = {
  "initial access": "초기 침투",
  "initial-access": "초기 침투",
  initial_access: "초기 침투",
  "초기침투": "초기 침투",
  execution: "실행",
  persistence: "지속성",
  "privilege escalation": "권한 상승",
  "privilege-escalation": "권한 상승",
  privilege_escalation: "권한 상승",
  "권한상승": "권한 상승",
  "defense evasion": "방어 회피",
  "defense-evasion": "방어 회피",
  defense_evasion: "방어 회피",
  "방어우회": "방어 회피",
  "credential access": "자격 증명 접근",
  "credential-access": "자격 증명 접근",
  credential_access: "자격 증명 접근",
  "자격증명": "자격 증명 접근",
  discovery: "탐색",
  "발견": "탐색",
  "lateral movement": "측면 이동",
  "lateral-movement": "측면 이동",
  lateral_movement: "측면 이동",
  "내부이동": "측면 이동",
  collection: "수집",
  "command and control": "명령 및 제어",
  "command-and-control": "명령 및 제어",
  command_and_control: "명령 및 제어",
  "command & control": "명령 및 제어",
  "명령제어": "명령 및 제어",
  exfiltration: "유출",
  impact: "영향",
};

const CATALOG: CatalogTechnique[] = [
  { id: "T1190", name: "공개 애플리케이션 취약점 악용", tactic: "초기 침투" },
  { id: "T1566.001", name: "스피어피싱 첨부파일", tactic: "초기 침투" },
  { id: "T1078", name: "유효 계정 사용", tactic: "초기 침투" },
  { id: "T1059", name: "명령 및 스크립팅 인터프리터", tactic: "실행" },
  { id: "T1059.001", name: "PowerShell", tactic: "실행" },
  { id: "T1059.003", name: "Windows 명령 셸", tactic: "실행" },
  { id: "T1059.004", name: "Unix 셸", tactic: "실행" },
  { id: "T1047", name: "Windows 관리 도구(WMI)", tactic: "실행" },
  { id: "T1204.002", name: "악성 파일 실행 유도", tactic: "실행" },
  { id: "T1136", name: "계정 생성", tactic: "지속성" },
  { id: "T1505.003", name: "웹 셸", tactic: "지속성" },
  { id: "T1547.001", name: "레지스트리 실행 키·시작 폴더", tactic: "지속성" },
  { id: "T1053.005", name: "예약 작업", tactic: "지속성" },
  { id: "T1068", name: "권한 상승 취약점 악용", tactic: "권한 상승" },
  { id: "T1548.002", name: "사용자 계정 컨트롤 우회", tactic: "권한 상승" },
  { id: "T1484.001", name: "그룹 정책 수정", tactic: "권한 상승" },
  { id: "T1027", name: "난독화된 파일 또는 정보", tactic: "방어 회피" },
  { id: "T1036", name: "위장", tactic: "방어 회피" },
  { id: "T1070.001", name: "Windows 이벤트 로그 삭제", tactic: "방어 회피" },
  { id: "T1562.001", name: "보안 도구 무력화", tactic: "방어 회피" },
  { id: "T1003", name: "운영체제 자격 증명 덤프", tactic: "자격 증명 접근" },
  { id: "T1003.001", name: "LSASS 메모리", tactic: "자격 증명 접근" },
  { id: "T1003.006", name: "DCSync", tactic: "자격 증명 접근" },
  { id: "T1110", name: "무차별 대입", tactic: "자격 증명 접근" },
  { id: "T1110.003", name: "패스워드 스프레이", tactic: "자격 증명 접근" },
  { id: "T1555", name: "암호 저장소의 자격 증명", tactic: "자격 증명 접근" },
  { id: "T1087", name: "계정 탐색", tactic: "탐색" },
  { id: "T1069.002", name: "도메인 그룹 탐색", tactic: "탐색" },
  { id: "T1082", name: "시스템 정보 탐색", tactic: "탐색" },
  { id: "T1049", name: "시스템 네트워크 연결 탐색", tactic: "탐색" },
  { id: "T1021", name: "원격 서비스", tactic: "측면 이동" },
  { id: "T1021.001", name: "원격 데스크톱 프로토콜", tactic: "측면 이동" },
  { id: "T1021.002", name: "SMB·Windows 관리자 공유", tactic: "측면 이동" },
  { id: "T1114", name: "이메일 수집", tactic: "수집" },
  { id: "T1005", name: "로컬 시스템의 데이터", tactic: "수집" },
  { id: "T1213", name: "정보 저장소의 데이터", tactic: "수집" },
  { id: "T1560.001", name: "유틸리티를 통한 아카이브", tactic: "수집" },
  { id: "T1071.001", name: "웹 프로토콜", tactic: "명령 및 제어" },
  { id: "T1105", name: "도구 전송", tactic: "명령 및 제어" },
  { id: "T1041", name: "C2 채널을 통한 유출", tactic: "유출" },
  { id: "T1567", name: "웹 서비스를 통한 유출", tactic: "유출" },
  { id: "T1486", name: "영향을 위한 데이터 암호화", tactic: "영향" },
  { id: "T1496", name: "리소스 하이재킹", tactic: "영향" },
];

function normalizedId(value: string) {
  const id = value.trim().toUpperCase();
  return /^T\d{4}(?:\.\d{3})?$/.test(id) ? id : "";
}

function normalizedTactic(value?: string) {
  if (!value?.trim()) return "기타";
  const trimmed = value.trim();
  return TACTIC_ALIASES[trimmed.toLowerCase()] || TACTIC_ALIASES[trimmed] ||
    (TACTICS.includes(trimmed as (typeof TACTICS)[number]) ? trimmed : "기타");
}

function tacticOrder(value: string) {
  const index = TACTICS.indexOf(value as (typeof TACTICS)[number]);
  return index === -1 ? TACTICS.length : index;
}

export function MitreTechniqueSelector({
  team,
  techniques,
  selected,
  disabled = false,
  onChange,
}: MitreTechniqueSelectorProps) {
  const [query, setQuery] = useState("");
  const [activeTactic, setActiveTactic] = useState("전체");

  const options = useMemo(() => {
    const byId = new Map<string, CatalogTechnique>(CATALOG.map((item) => [item.id, item]));
    for (const item of techniques) {
      const id = normalizedId(item.id);
      if (!id) continue;
      const catalog = byId.get(id);
      byId.set(id, {
        id,
        name: item.name?.trim() || catalog?.name || "ATT&CK 기술",
        tactic: item.tactic?.trim() ? normalizedTactic(item.tactic) : catalog?.tactic || "기타",
        contextual: true,
      });
    }
    return [...byId.values()].sort((left, right) =>
      Number(Boolean(right.contextual)) - Number(Boolean(left.contextual)) ||
      tacticOrder(left.tactic) - tacticOrder(right.tactic) ||
      left.id.localeCompare(right.id),
    );
  }, [techniques]);

  const selectedIds = useMemo(
    () => [...new Set(selected.map(normalizedId).filter(Boolean))],
    [selected],
  );
  const selectedSet = useMemo(() => new Set(selectedIds), [selectedIds]);
  const normalizedQuery = query.trim().toLocaleLowerCase("ko-KR");
  const visibleOptions = options.filter((item) => {
    const tacticMatches = activeTactic === "전체" || item.tactic === activeTactic;
    const queryMatches =
      !normalizedQuery ||
      `${item.id} ${item.name} ${item.tactic}`.toLocaleLowerCase("ko-KR").includes(normalizedQuery);
    return tacticMatches && queryMatches;
  });
  const visibleGroups = TACTICS.flatMap((tactic) => {
    const items = visibleOptions.filter((item) => item.tactic === tactic);
    return items.length > 0 ? [{ tactic, items }] : [];
  }).sort((left, right) => {
    const leftHasContext = left.items.some((item) => item.contextual);
    const rightHasContext = right.items.some((item) => item.contextual);
    return Number(rightHasContext) - Number(leftHasContext) ||
      tacticOrder(left.tactic) - tacticOrder(right.tactic);
  });
  const tacticCounts = new Map(
    TACTICS.map((tactic) => [tactic, options.filter((item) => item.tactic === tactic).length]),
  );

  const toggle = (id: string) => {
    if (disabled) return;
    onChange(selectedSet.has(id) ? selectedIds.filter((value) => value !== id) : [...selectedIds, id]);
  };

  return (
    <section className={`mitre-selector mitre-selector--${team}`} aria-label="MITRE ATT&CK 기술 선택">
      <header className="mitre-selector__header">
        <div>
          <span>{team === "blue" ? "BLUE TEAM MAPPING" : "RED TEAM MAPPING"}</span>
          <h4>MITRE ATT&amp;CK 기술 선택</h4>
          <p>관찰한 행위에 해당하는 기술을 모두 선택하세요. 여러 기술을 함께 제출할 수 있습니다.</p>
        </div>
        <strong aria-live="polite">{selectedIds.length}개 선택</strong>
      </header>

      {selectedIds.length > 0 && (
        <div className="mitre-selector__selected" aria-label="선택한 MITRE ATT&CK 기술">
          <span>선택됨</span>
          {selectedIds.map((id) => {
            const option = options.find((item) => item.id === id);
            return (
              <button key={id} type="button" onClick={() => toggle(id)} disabled={disabled} title={`${id} 선택 해제`}>
                <b>{id}</b>
                <span>{option?.name || "ATT&CK 기술"}</span>
                <i aria-hidden="true">×</i>
              </button>
            );
          })}
        </div>
      )}

      <div className="mitre-selector__toolbar">
        <label>
          <span aria-hidden="true">⌕</span>
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="기술 ID, 한글명, 전술 검색"
            aria-label="MITRE ATT&CK 기술 검색"
            disabled={disabled}
          />
          {query && (
            <button type="button" onClick={() => setQuery("")} disabled={disabled} aria-label="검색어 지우기">
              ×
            </button>
          )}
        </label>
        <span>{visibleOptions.length} / {options.length}개 기술</span>
      </div>

      <div className="mitre-selector__tactics" role="group" aria-label="ATT&CK 전술 필터">
        <button
          type="button"
          className={activeTactic === "전체" ? "is-active" : ""}
          onClick={() => setActiveTactic("전체")}
          disabled={disabled}
        >
          전체 <span>{options.length}</span>
        </button>
        {TACTICS.filter((tactic) => (tacticCounts.get(tactic) || 0) > 0).map((tactic) => (
          <button
            type="button"
            className={activeTactic === tactic ? "is-active" : ""}
            onClick={() => setActiveTactic(tactic)}
            disabled={disabled}
            key={tactic}
          >
            {tactic} <span>{tacticCounts.get(tactic)}</span>
          </button>
        ))}
      </div>

      <div className="mitre-selector__matrix">
        {visibleGroups.length === 0 ? (
          <div className="mitre-selector__empty">
            <strong>일치하는 기술이 없습니다.</strong>
            <span>검색어를 바꾸거나 전체 전술을 선택해 주세요.</span>
          </div>
        ) : (
          visibleGroups.map((group) => (
            <section className="mitre-tactic-group" key={group.tactic}>
              <div className="mitre-tactic-group__heading">
                <strong>{group.tactic}</strong>
                <span>{group.items.length}</span>
              </div>
              <div>
                {group.items.map((item) => {
                  const isSelected = selectedSet.has(item.id);
                  return (
                    <button
                      type="button"
                      className={isSelected ? "mitre-technique is-selected" : "mitre-technique"}
                      aria-pressed={isSelected}
                      onClick={() => toggle(item.id)}
                      disabled={disabled}
                      key={item.id}
                    >
                      <span className="mitre-technique__check" aria-hidden="true">{isSelected ? "✓" : "+"}</span>
                      <span>
                        <b>{item.id}</b>
                        <strong>{item.name}</strong>
                      </span>
                    </button>
                  );
                })}
              </div>
            </section>
          ))
        )}
      </div>
    </section>
  );
}
