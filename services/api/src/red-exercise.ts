import { createHash } from "node:crypto";

import type { JsonObject } from "./types.ts";

export type RedExerciseProfile =
  | "command_injection"
  | "path_traversal"
  | "sql_injection"
  | "auth_bypass"
  | "sensitive_data_exposure";

export interface RedExerciseSpec extends JsonObject {
  schemaVersion: 1;
  profile: RedExerciseProfile;
  scenarioId: string;
  title: string;
  summary: string;
  expectedCves: string[];
  service: {
    scheme: "http";
    host: "target";
    port: 8080;
    baseUrl: "http://target:8080";
  };
  verification: {
    method: "GET";
    path: string;
    successMarker: string;
  };
  attackTechniqueIds: string[];
  simulationMode: "bounded_behavioral";
}

/**
 * Converts learner intent into a bounded local target behavior. The prompt can
 * select only an operator-owned profile; it can never provide code, commands,
 * an image, a route, or a success marker to the runtime.
 */
export function buildRedExercise(input: {
  title: string;
  prompt: string;
  cveIds: string[];
  attackTechniqueIds: string[];
}): RedExerciseSpec {
  const title = boundedText(input.title, 120, "Red Team Lab");
  const prompt = boundedText(input.prompt, 5_000, "격리된 대상의 취약 조건을 검증합니다.");
  const cveIds = [...new Set(input.cveIds.map((item) => item.toUpperCase()))]
    .filter((item) => /^CVE-\d{4}-\d{4,7}$/.test(item))
    .slice(0, 20);
  const techniqueIds = [...new Set(input.attackTechniqueIds.map((item) => item.toUpperCase()))]
    .filter((item) => /^T\d{4}(?:\.\d{3})?$/.test(item))
    .slice(0, 20);
  const profile = selectProfile(`${title}\n${prompt}\n${cveIds.join(" ")}`.toLowerCase());
  const scenarioId = createHash("sha256")
    .update(`${title}\n${prompt}\n${cveIds.join(",")}\n${profile.id}`)
    .digest("hex")
    .slice(0, 16);

  return {
    schemaVersion: 1,
    profile: profile.id,
    scenarioId: `red-${scenarioId}`,
    title,
    summary: profile.summary,
    expectedCves: cveIds,
    service: {
      scheme: "http",
      host: "target",
      port: 8_080,
      baseUrl: "http://target:8080",
    },
    verification: {
      method: "GET",
      path: profile.verificationPath,
      successMarker: profile.successMarker,
    },
    attackTechniqueIds: techniqueIds.length > 0 ? techniqueIds : profile.defaultTechniques,
    simulationMode: "bounded_behavioral",
  };
}

function selectProfile(value: string): {
  id: RedExerciseProfile;
  summary: string;
  verificationPath: string;
  successMarker: string;
  defaultTechniques: string[];
} {
  if (/(sql\s*injection|sqli|union\s+select|database|데이터베이스|에스큐엘|CVE-2023-34362)/i.test(value)) {
    return {
      id: "sql_injection",
      summary: "검색 API의 입력값 처리 결함을 이용해 허용 범위를 벗어난 레코드가 조회되는 조건을 확인하는 격리형 SQL 인젝션 실습입니다.",
      verificationPath: "/api/users?id=1%20OR%201=1",
      successMarker: "ZEROTOP_SQL_INJECTION_CONFIRMED",
      defaultTechniques: ["T1190"],
    };
  }
  if (/(path\s*traversal|directory\s*traversal|lfi|local\s*file|파일\s*포함|경로\s*탐색|디렉터리\s*트래버설|CVE-2021-41773)/i.test(value)) {
    return {
      id: "path_traversal",
      summary: "다운로드 경로 정규화 결함으로 애플리케이션 허용 디렉터리 밖의 합성 파일을 읽을 수 있는 조건을 확인하는 격리형 실습입니다.",
      verificationPath: "/download?file=../../../../etc/passwd",
      successMarker: "ZEROTOP_PATH_TRAVERSAL_CONFIRMED",
      defaultTechniques: ["T1190", "T1005"],
    };
  }
  if (/(auth(?:entication)?\s*bypass|인증\s*우회|권한\s*우회|unauth|access\s*control|CVE-2023-22515|CVE-2022-40684)/i.test(value)) {
    return {
      id: "auth_bypass",
      summary: "신뢰되지 않은 역할 파라미터 때문에 인증 없이 관리 기능에 접근할 수 있는 조건을 확인하는 격리형 접근통제 실습입니다.",
      verificationPath: "/admin?role=admin",
      successMarker: "ZEROTOP_AUTH_BYPASS_CONFIRMED",
      defaultTechniques: ["T1190", "T1078"],
    };
  }
  if (/(rce|remote\s*code|command\s*injection|명령어\s*삽입|원격\s*코드|코드\s*실행|log4j|log4shell|shell|CVE-2021-44228)/i.test(value)) {
    return {
      id: "command_injection",
      summary: "진단 API의 입력값 검증 결함을 통해 제한된 합성 명령 결과가 노출되는 조건을 확인하는 격리형 원격 코드 실행 실습입니다.",
      verificationPath: "/api/diagnostics?host=127.0.0.1%3Bid",
      successMarker: "ZEROTOP_COMMAND_INJECTION_CONFIRMED",
      defaultTechniques: ["T1190", "T1059.004"],
    };
  }
  return {
    id: "sensitive_data_exposure",
    summary: "운영 환경에서 비활성화되어야 할 디버그 뷰를 통해 합성 구성 정보가 노출되는 조건을 확인하는 격리형 웹 취약점 실습입니다.",
    verificationPath: "/api/debug?view=config",
    successMarker: "ZEROTOP_SENSITIVE_DATA_EXPOSURE_CONFIRMED",
    defaultTechniques: ["T1190", "T1005"],
  };
}

function boundedText(value: string, maximum: number, fallback: string): string {
  const normalized = value.replace(/[\u0000-\u001f\u007f]+/g, " ").replace(/\s+/g, " ").trim();
  return (normalized || fallback).slice(0, maximum);
}
