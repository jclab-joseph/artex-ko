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
>
> docker-compose e2e(`e2e/run.sh`)가 Bash·`__artex_dns`·샌드박스 트래픽 캡처→조회
> →증거 동기화·pin/unpin 을 검증합니다. 남은 범위(Agent 호스팅 MCP)는 "로드맵" 참고.

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
| MCP(github 등 제어판 도구) | — *(Agent 호스팅 MCP 는 로드맵)* |
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

**남은 범위**

1. **Agent 호스팅 MCP(선택적 라우팅)**: 현재 모든 MCP 는 제어판에서 동작합니다(github 등
   제어판 도구에 적합 — Agent 가 MCP 이름을 announce 하지 않으므로 backend 가 래핑하지
   않음). "표적 도구 MCP 를 Agent 에서" 하려면 Agent 가 해당 MCP 클라이언트를 호스팅하고
   그 도구 이름을 announce 하면 됩니다(라우팅 메커니즘은 이미 backend.Executes 로 지원).
   MCP 설정 전달·전송·수명주기를 Agent 에 추가하는 것이 남은 구현입니다.
2. **인증서 자동 로테이션**(현재는 재프로비저닝) — 선택.
3. **traffic 증거 oversize 처리**(현재 8MiB 초과 본문은 동기화 불가·명시적 오류):
   `traffic_blob` 레인지 재조립으로 대용량 증거 동기화 — 선택(대부분 증거는 상한 이하).
   다중 Agent 환경에서 증거는 현재 최신 Agent(`ExecAny`)에서 가져오므로, 캡처 Agent 가
   여럿일 때 핀 기반 증거 라우팅도 함께 고려.

## 코드 지도

- `remoteexec/` — 프레임 프로토콜(`proto.go`)·양방향 멀티플렉서(`mux.go`)·mTLS·CA·번들
  (`pki.go`)·원격 프록시 도구와 Agent 디스패처(`exec.go`)·전송(`transport.go`)·
  백엔드 추상화와 fail-closed(`backend.go`)·in-proc(`inproc.go`)·출구 환경(`egress.go`).
- `execsvc/` — db/server 비의존 실행 서비스: script·http·dns·httpprobe(`__artex_*`),
  Agent 가 호스팅(모델 비노출, 제어판이 프로그램적으로 호출).
- `agentctl/` — 제어판 CA·Agent 레지스트리·리스너/dial·번들 발급·진단 실행·작업 핀(`manager.go`).
- `cmd/artex-agent/` — 실행면 바이너리(LLM·시크릿·DB 무의존).
- `cmd/artex/` — `issue-agent` 서브커맨드 추가.
- `agent/assembly.go` — `AugmentTools` 에서 backend 로 실행계 도구를 RPC 프록시로 래핑
  (`RemoteWebFetchActive`/`InjectRemoteWebFetch`/`ExecBashEnv` 헬퍼, 4개 역할 공통).
- `server/agents.go` — `/api/exec-agents` 핸들러 + 엔진 backend 리졸버 + enrich 프로버 배선.
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
