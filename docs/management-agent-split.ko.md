# Management Server ↔ Agent 실행면 분리

ARTEX 를 **제어판(Management Server)** 과 **실행면(Agent)** 으로 나눠, 위험한 작업을
인터넷과 분리된 사용자 샌드박스 안에서만 실행하도록 하는 구조입니다. 제어판은 LLM 루프와
모든 LLM 시크릿을 쥐고, 실행면은 오직 도구 실행만 합니다.

> **상태**: 구현 진행 중. 다음이 양방향 mTLS 채널을 통해 샌드박스 Agent 에서 실행됩니다.
> - **P1**: Bash·파일 I/O(Read/Write/Edit/MultiEdit/LS/Glob/Grep)·WebFetch·Sleep.
> - **P2-A**: 커맨드형 커스텀 도구의 Bash.
> - **P2-B**: 커스텀 script/http 도구, enrich 의 DNS·HTTP 프로브(`execsvc` 내부 서비스).
> - **P2-C**: 작업별 Agent 핀 고정(다중 Agent 라우팅).
> - **P2-D**: traffic 기록 스토어(MITM 프록시+SQLite 인덱스+blob)와 조회 도구
>   (traffic_search/get/blob)를 Agent 에서 호스팅. 바인딩 시점 증거는
>   `__artex_traffic_evidence` 로 제어판에 동기화(스냅샷 후 리포트는 Agent 비의존).
> - **P2-E**: 서버별 선택적 **Agent 호스팅 MCP**. agent-hosted 로 표시된 MCP 서버는
>   샌드박스 Agent 가 호스팅(stdio=샌드박스 자식프로세스)하고, 제어판은 announce 메타로
>   placeholder 를 만들어 백엔드로 라우팅. github 등은 종전대로 제어판.
>
> docker-compose e2e(`e2e/run.sh`)가 Bash·`__artex_dns`·샌드박스 트래픽 캡처→조회
> →증거 동기화·**Agent 호스팅 MCP**·pin/unpin 을 검증합니다.

## 왜 포크 없이 되는가 (핵심 설계)

LLM 루프와 도구 실행은 둘 다 외부 모듈 `norma`(`agentcore.Session.Prompt`) 안에서
한 세션으로 돕니다. 하지만 artex 는 모든 도구를 `opts.Tools` 로 **직접** 넘기고
(`agent/assembly.go` `AugmentTools`), 모든 도구 호출이 `guardedTool.Call` 한 지점을
지납니다. 그래서 **루프는 제어판(LLM 보유)에 그대로 두고, 실행계 도구의 `CoreTool.Call`
구현만 "Agent 로의 RPC 프록시"로 바꿔 끼우면** 됩니다. norma 루프 포크가 필요 없습니다.

```
norma 루프(Management, LLM)                  샌드박스 Agent(LLM 없음)
  └ PreToolUse 게이트(정책·LLM심판·사람승인)      └ 실제 Bash/WebFetch/스캐너 실행
       └ guardedTool.Call ── mTLS ──────────────▶  (결과) ──────────┘
```

PreToolUse 게이트(intercept 규칙, LLM 심판, 사람 승인)는 디스패치 **이전에** 제어판에서
돕니다. 따라서 승인·심판은 제어판에, 부수효과는 샌드박스에 남습니다.

## 어디가 어디로 갔나

| 제어판(Management) | 실행면(Agent, 샌드박스) |
|---|---|
| LLM provider·`llmpool`·`llmrec`·API 키 | **없음(절대)** |
| `agentcore` 루프(worker/planner/mainagent/chat) | 없음 |
| `guard`/`intercept` 정책·승인 | 없음 |
| Postgres(assets/findings/exploration/settings) | 없음(로컬 작업 디렉터리뿐) |
| HTTP API·UI·스케줄러·notifier | 없음 |
| web_search(검색엔진=정찰, 표적 아님) | — |
| MCP(github 등 제어판 도구; `agent_hosted=false`) | MCP(`agent_hosted=true`; stdio=샌드박스 자식프로세스, http/sse=샌드박스 내 엔드포인트) |
| 커스텀 도구 정의·템플릿·시크릿 주입 | 커스텀 **command/script/http 실행부** |
| enrich 엔진·자산 그래프 쓰기(DB) | enrich **DNS·HTTP 프로브** 네트워크 I/O |
| traffic 조회 도구를 **RPC 프록시/메타로만** 보유 | traffic **MITM 프록시·SQLite 인덱스·blob 스토어** + traffic_search/get/blob 실행 |
| 바인딩된 증거 **스냅샷·리포트 렌더링**(영구) | `__artex_traffic_evidence` 로 **증거 원문 바이트 제공**(동기화 시) |
| 실행계 도구를 **RPC 프록시로만** 보유 | **Bash/파일/WebFetch/Sleep** 실제 실행 |

Agent 바이너리(`cmd/artex-agent`)는 `server`·`db`·`llmpool`·`agentcore` 를 import 조차
하지 않습니다(컴파일 타임 보장). 유일하게 `norma/llm` 의 **데이터 타입**(tool.Result 용
ContentBlock)만 들어오며, provider·시크릿·네트워크는 없습니다.

## 통신: 양방향 mTLS

연결 방향(누가 dial 하나)과 RPC 방향(누가 도구 실행을 지시하나)을 분리합니다. 하나의
mTLS 연결 위에서 프레임 멀티플렉서(`remoteexec`)가 호출/결과/진행/이벤트를 실어 나릅니다.

- **agent-dials-mgmt** (`ModeAgentDials`): Agent 가 제어판으로 dial. 제어판이 listen.
  Agent 는 10일 임시 클라이언트 인증서를 제시, 제어판은 CA 로 검증.
- **mgmt-dials-agent** (`ModeMgmtDials`): 제어판이 Agent 로 dial. Agent 가 listen.
  **hostname 검증 생략**(샌드박스 주소가 가변) → `InsecureSkipVerify` + CA 서명·
  CommonName(`artex-agent:<id>`) 핀으로 대체. 양방향 모두 상호 인증(mTLS) 유지.

인증서: 제어판이 CA 를 보유(`<data>/agent-ca.crt|key`). Agent 인증서는 **10일**짜리로
발급하며, 만료 시 **재프로비저닝**(새 번들로 샌드박스 재기동)으로 교체합니다(자동 갱신 없음).

### 연결 번들

제어판은 "연결 정보"만 만들고, 샌드박스 실행은 사용자가 직접 합니다. 번들은
`{mode, agent_id, address, ca_cert, agent_cert+key, expires}` JSON 입니다.

```bash
# 제어판 호스트(CA 가 있는 data 디렉터리)에서 발급
artex issue-agent -data /app/data -mode agent-dials-mgmt \
  -address management.example.com:8790 -id prod-agent-1 -out bundle.json

# 사용자가 자기 샌드박스 안에서 Agent 실행
artex-agent --bundle bundle.json --work /work \
  --egress-proxy http://127.0.0.1:8788 --egress-ca /work/_ca/mitmproxy-ca-cert.pem
```

HTTP API 로도 발급·조회할 수 있습니다(로그인 필요):

- `POST /api/exec-agents/bundle` `{mode,address,agent_id?}` → 번들 JSON 다운로드
- `GET  /api/exec-agents` → 연결된 Agent 목록 + 오프로드 모드
- `POST /api/exec-agents/dial` `{agent_id,address}` → mgmt-dials 모드로 Agent 에 접속
- `POST /api/exec-agents/{id}/exec` `{tool,input}` → 진단용 단발 실행(LLM 미경유)

## 설정(환경 변수)

| 변수 | 의미 |
|---|---|
| `ARTEX_AGENT_LISTEN` | Agent 가 dial-in 할 제어판 수신 주소(예 `:8790`). 비우면 미수신(대신 `/dial`). |
| `ARTEX_AGENT_OFFLOAD` | `off`(기본·단일 프로세스 그대로) / `auto`(연결돼 있으면 오프로드) / `require`(샌드박스 필수, 미연결 시 **fail-closed**) |

Agent 측: `--bundle`(또는 `ARTEX_AGENT_BUNDLE`), `--work`, `--egress-proxy`, `--egress-ca`,
`--reconnect`, 그리고 traffic 호스팅용:

| 변수/플래그 | 의미 |
|---|---|
| `--traffic` / `ARTEX_AGENT_TRAFFIC` | ARTEX 기록 MITM 프록시+증거 스토어를 샌드박스 안에서 호스팅. 켜면 Agent 툴체인(Bash/WebFetch/execsvc)의 egress 가 이 레코더를 통과하므로 모든 target 교환이 샌드박스에서 캡처되고, 제어판은 traffic_search/get/blob 로 조회·`__artex_traffic_evidence` 로 증거를 동기화한다. `--egress-proxy` 를 함께 주면 레코더의 상위 프록시로 체이닝. |
| `--traffic-addr` / `ARTEX_AGENT_TRAFFIC_ADDR` | 호스팅 레코더 수신 주소(기본 `127.0.0.1:8788`). |

분리 모드에서는 제어판을 `-proxy ""`(로컬 기록 끔)로 띄우고, 기록은 Agent 의 `--traffic`
가 담당합니다. 제어판의 traffic 조회 도구는 capture 토글이 켜지고 `offload != off` 일 때
메타데이터로 주입되어 백엔드가 Agent 로 라우팅합니다(미연결 시 fail-closed).

### MCP 호스팅 설정

MCP 서버를 Agent(샌드박스)에서 호스팅하려면 두 경로가 있습니다.

- **DB/UI 경로**: `mcp_servers.agent_hosted=true`. MCP API 로 설정합니다 —
  `POST /api/mcp` 본문에 `"agent_hosted": true`. 이후 `POST /api/exec-agents/bundle` 로
  번들을 발급하면 agent-hosted 로 표시된(enabled) 서버 설정이 번들에 스냅샷됩니다.
- **CLI 경로(DB 불필요)**: `artex issue-agent -mcp <file.json>` — `mcpconn.Config` 배열
  JSON 을 번들에 주입합니다. 예: `[{"name":"mysrv","transport":"stdio","command":"/usr/local/bin/mymcp"}]`.

설정은 발급 시 스냅샷이므로 **MCP 구성 변경 시 번들을 재발급**(샌드박스 재기동)하세요
(인증서 모델과 동일). env 맵은 http/sse 전송에서 HTTP 헤더(예: Authorization)로도 쓰입니다.

**보안 자세**: 운영에서는 `ARTEX_AGENT_OFFLOAD=require` 를 권장합니다. 이때 Agent 가 없으면
실행계 도구는 "플랫폼 관리·실행면 미준비" 오류로 **차단**되고, 데이터/그래프 도구(record_fact 등)만
제어판에서 계속 동작합니다. `off`/`auto` + 미연결이면 종전처럼 in-process 로 실행됩니다.

## 네트워크 egress 경계(결정됨)

**표적 지향 네트워크 I/O 만 Agent.** LLM API·IM 알림·self-update·MCP 레지스트리 등
제어판 egress 는 종전처럼 인터넷 자유 연결입니다. Bash(스캐너 포함)·WebFetch·파일 I/O 는
Agent 로, web_search 는 제어판에 남습니다.

## e2e

`e2e/run.sh` 는 바이너리 2종을 빌드하고 `e2e/docker-compose.yml`(postgres+management+
provision+agent+target)를 띄운 뒤, 제어판에서 **Agent 를 거쳐 mTLS 로** 다음을 검증합니다
(LLM 키 불필요):

- Bash 실행(마커 + Agent 컨테이너 hostname 반환),
- `__artex_dns` 실행 서비스,
- 샌드박스 트래픽 캡처→조회: Agent 가 자신의 호스팅 레코더를 거쳐 `http://target/` 를
  fetch 한 뒤 제어판이 `traffic_search` 로 캡처된 교환을 되받음,
- 증거 동기화: `__artex_traffic_evidence` 로 교환 원문 바이트(base64)를 샌드박스에서 가져옴,
- Agent 호스팅 MCP: Agent 가 샌드박스에서 stdio MCP 서버(`e2e/mcpstub`)를 호스팅하고
  `mcp__e2estub__echo` 를 announce, 제어판이 그 도구를 채널로 구동해 echo 를 되받음,
- 작업 pin/unpin, 미지 도구 거부(negative).

```bash
e2e/run.sh            # 빌드·기동·검증·정리
KEEP=1 e2e/run.sh     # 검증 후 스택 유지(디버깅)
```

## 로드맵

**완료**

- ~~enrich(DNS·HTTP 프로브)를 Agent 로~~ — P2-B. 엔진·자산 쓰기는 제어판, 네트워크
  I/O 만 `execsvc` 로 Agent 에서 수행. `offload=auto` 미연결 시 로컬 폴백, `require`
  미연결 시 skip.
- ~~커스텀 도구(command/script/http) 실행부를 Agent 로~~ — P2-A/B. 정의·템플릿은 제어판,
  실행만 `execsvc`(db/server 비의존)로 Agent.
- ~~태스크↔Agent 핀 고정 + 다중 Agent 라우팅~~ — P2-C.
- ~~traffic MITM 프록시 + SQLite 증거 스토어 + 조회 도구를 Agent 로~~ — P2-D. Agent 가
  `--traffic` 로 레코더를 호스팅(툴체인 egress 가 통과 → 샌드박스 캡처). 조회 도구는
  제어판에 메타로 주입되어 백엔드가 Agent 로 라우팅. 바인딩 시점 증거는
  `__artex_traffic_evidence`(db-free, 모델 비노출)로 제어판에 동기화해 기존 증거 스토어에
  스냅샷하므로 **리포트 렌더링은 Agent 비의존**. per-body 8MiB 인라인 상한(초과=oversize,
  truncate 없음). **traffic 패키지의 유일한 Postgres(db) 결합(`db.TemplatePath`)은
  db-free 복제본으로 제거** — Agent 바이너리가 db 를 링크하지 않는 불변식 유지.
- ~~Agent 호스팅 MCP(서버별 선택적 라우팅)~~ — P2-E. `mcp_servers.agent_hosted=true` 인
  서버는 샌드박스 Agent 가 호스팅(stdio=샌드박스 자식프로세스; http/sse=샌드박스 엔드포인트).
  구현의 핵심은 **announce 에 전체 툴 메타(스키마) 추가** — 제어판은 MCP 툴의 로컬 정의가
  없으므로, Agent 가 보낸 메타로 placeholder 를 만들어 백엔드로 Agent 에 라우팅한다(가시성·
  skill-gating·unlock 로직 그대로). 설정은 발급 시 번들에 스냅샷(변경=재발급); env(헤더/
  토큰 등 툴 시크릿)만 Agent 로 가며 **LLM 시크릿은 절대 아님**. 공유 연결 로직은 db-free
  `mcpconn`(server·Agent 공용). github 등은 종전대로 제어판.

**남은 범위**

없음 — 사용자 결정 범위의 분리 작업은 모두 완료. 선택적 보완은 "알려진 제약" 참고.

**비범위(결정됨)**

- **인증서 자동 로테이션**: 구현하지 않습니다. Agent 는 일회성(샌드박스와 수명을 같이함)
  이므로, 10일 인증서가 만료되면 **재프로비저닝**(새 번들로 샌드박스 재기동)으로 충분합니다.

## 알려진 제약 (분리 모드)

아래는 현재 **비지원**이며, 보안 요건(위험 작업의 샌드박스 격리)과는 무관한 기능 완성도
항목입니다. 분리 모드 운영 시 참고하세요.

- **대용량 증거(>8MiB) 동기화 미지원**: `__artex_traffic_evidence` 는 요청/응답 본문을
  한 번의 RPC 프레임으로 인라인(base64) 전송하므로, 전송 프레임이 전송 상한(64MiB)을
  넘지 않도록 **per-body 8MiB 인라인 상한**을 둡니다. 초과 본문은 **truncate 하지 않고**
  `oversize` 플래그로 표시되며, 제어판은 이를 명시적 오류(`ErrEvidenceOversize`)로
  처리합니다(절대 잘린 증거를 저장하지 않음 — 증거 무결성 우선). 대부분의 취약점 증거는
  상한 이하라 영향이 없습니다. 초과가 필요하면 `traffic_blob` 레인지로 본문을 조각내
  재조립하는 방식으로 확장할 수 있으나, 현재 범위에서 **제외**합니다. 대용량 증거가
  필요한 경우에는 샌드박스 안에서 직접 리포트를 생성하는 운영을 권장합니다.
- **다중 캡처 Agent 시 증거 출처**: 증거 동기화는 현재 **가장 최근 연결된 Agent**
  (`ExecAny`)에서 가져옵니다. 캡처 Agent 가 둘 이상일 때는 인용된 교환을 실제로 캡처한
  Agent 와 다를 수 있으므로, 핀 기반 증거 라우팅이 필요하면 별도로 고려하세요(단일 샌드박스
  배포에서는 문제 없음).
- **task 아카이브의 원시 트래픽 export**: 분리 모드(`m.traffic == nil`)에서는 task
  아카이브가 호스트별 원시 트래픽(`ExportHosts`)을 포함하지 않습니다. 다만 **취약점에
  바인딩된 증거는 제어판 증거 스토어에 스냅샷**되어 있으므로(바인딩 시점 동기화), 아카이브는
  이 스냅샷을 그대로 보존합니다 — 리포트에 필요한 증거는 유실되지 않습니다. 유실되는 것은
  바인딩되지 않은 원시 캡처뿐이며, 이는 일회성 샌드박스와 함께 폐기됩니다.
- **제어판 global egress proxy 설정은 분리 모드에서 무효**: 레코더가 Agent 에 있으므로
  상위 egress 는 Agent 기동 시 `--egress-proxy` 로 지정합니다. UI 의 global proxy 설정
  (`SetGlobalProxy`)은 로컬 레코더(`m.traffic`)를 대상으로 하므로 분리 모드에서는 효과가
  없습니다.
- **Agent 트래픽 스토어의 수명·관리**: Agent 의 SQLite 인덱스·blob 트리는 샌드박스 안에
  있으며, 제어판의 트래픽 삭제/GC/보존 정책(`DeleteHost`/`DeleteAll` 등)은 적용되지
  않습니다. 일회성 샌드박스 전제에서는 스토어가 샌드박스와 함께 폐기되므로 수용 가능합니다.
- **Agent 호스팅 MCP 의 제약**: (1) 설정은 번들 스냅샷이라 변경 시 재발급 필요(위 참고).
  (2) 인터넷과 분리된 샌드박스에서는 외부 http/sse MCP 로 나가는 연결이 막히므로, Agent
  호스팅 MCP 는 stdio(샌드박스 내 프로세스) 또는 샌드박스 네트워크 안의 엔드포인트가
  적합합니다. 외부 SaaS MCP(github 등)는 제어판 호스팅으로 두세요. (3) `agent_hosted`
  는 MCP 설정 페이지의 "샌드박스 Agent 에서 호스팅" 체크박스, MCP API(json), 또는
  CLI `-mcp` 로 설정합니다.

## 웹 UI

실행면 분리를 제어판 웹 UI 에서 운용할 수 있습니다.

- **시스템 → 실행 Agent**(`/system/exec-agents`): 연결된 샌드박스 Agent 목록(모드·도구·
  접속 시각), offload 자세(off/auto/require)·수신 주소, **연결 번들 발급+다운로드**,
  mgmt-dials 접속(dial), 작업 pin/unpin. 분리 비활성(서버 503) 시 활성화 방법을 안내.
  LLM 페르소나 페이지(`/system/agents`)와는 구분됩니다.
- **시스템 → MCP**: 서버별 "샌드박스 Agent 에서 호스팅"(`agent_hosted`) 체크박스 + 목록 배지.
- **시스템 → 시스템 설정**: 분리 모드일 때 traffic capture·global proxy 항목에 의미 변화
  안내(기록은 Agent `--traffic`, 상위는 Agent `--egress-proxy`, global proxy 무효).
- **사이드바 자세 배지**: 분리 모드일 때 offload 모드 + 연결 Agent 수를 상시 표시
  (Agent 0 이면 경고색), 클릭 시 실행 Agent 페이지로 이동.

## 코드 지도

- `remoteexec/` — 프레임 프로토콜(`proto.go`)·양방향 멀티플렉서(`mux.go`)·mTLS·CA·번들
  (`pki.go`)·원격 프록시 도구와 Agent 디스패처(`exec.go`)·전송(`transport.go`)·
  백엔드 추상화와 fail-closed(`backend.go`)·in-proc(`inproc.go`)·출구 환경(`egress.go`).
- `execsvc/` — db/server 비의존 실행 서비스: script·http·dns·httpprobe(`__artex_*`),
  Agent 가 호스팅(모델 비노출, 제어판이 프로그램적으로 호출).
- `mcpconn/` — db/server 비의존 MCP 연결 헬퍼(transport 무관 Config + Connect:
  stdio=norma/mcp, http/sse=mcphttp). server·Agent 공용(Agent 가 db 를 링크하지 않도록).
- `remoteexec/announce.go` — 툴 announce 메타(WireToolMeta), Executor.ToolMetas,
  CoreToolFromMeta/NewRemoteToolFromMeta(제어판이 로컬 정의 없는 Agent 툴을 프록시).
- `agentctl/` — 제어판 CA·Agent 레지스트리·리스너/dial·번들 발급·진단 실행·작업 핀(`manager.go`).
- `cmd/artex-agent/` — 실행면 바이너리(LLM·시크릿·DB 무의존).
- `cmd/artex/` — `issue-agent` 서브커맨드 추가.
- `agent/assembly.go` — `AugmentTools` 에서 backend 로 실행계 도구를 RPC 프록시로 래핑
  (`RemoteWebFetchActive`/`InjectRemoteWebFetch`/`ExecBashEnv` 헬퍼, 4개 역할 공통).
- `server/agents.go` — `/api/exec-agents` 핸들러 + 엔진 backend 리졸버 + enrich 프로버 배선
  + 번들에 agent-hosted MCP 설정 주입.
- `server/mcpdiscover.go` — `mcpHostedTools`(agent-hosted 서버는 로컬 연결 대신 announce
  메타 기반 placeholder) + `agentHostedMCPConfigs`(번들용) + `mcpConfigFromDB`.
- `server/assembly.go` — MCP 조립 시 agent-hosted 서버를 `mcpHostedTools` 로 처리(로컬
  connectMCP 스킵).
- `server/engine.go` — `bindExecBackend` 로 planner/worker 실행 컨텍스트에 backend 주입.
- `server/customtool.go` — command/script/http 커스텀 도구를 backend/execsvc 로 라우팅.
- `enrich/enrich.go` — `Prober` 인터페이스로 DNS/HTTP 프로브를 Agent 로(로컬 폴백 포함).
- `traffic/` — 기록 MITM 프록시+SQLite 인덱스+blob 스토어+조회 도구(`traffic.go`).
  `nkey.go` 는 db-free `templatePath`(Postgres 결합 제거). `RemoteToolMetas` 는 분리
  모드용 nil-safe 메타. `evidence_service.go` 는 Agent 가 호스팅하는 증거 동기화 서비스
  `__artex_traffic_evidence`(와이어 타입 공유, 모델 비노출).
- `evidence/store.go` — `Store.Traffic` 을 `TrafficEvidence` 인터페이스로(로컬=`*traffic.Traffic`,
  분리 모드=원격 어댑터). 바인딩 시점만 소스를 쓰고 읽기 경로는 영구 스냅샷을 서빙.
- `server/evidence_remote.go` — `remoteEvidenceSource`: 분리 모드 증거 소스. `ExecAny` 로
  `__artex_traffic_evidence` 를 id 단위 호출해 EvidenceExchange 재구성.
- `server/orchestration.go` — `trafficHostTools`: 로컬 레코더 있으면 실도구, 분리 모드면
  `traffic.RemoteToolMetas` 주입(백엔드가 Agent 로 라우팅).
