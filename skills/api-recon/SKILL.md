---
name: api-recon
description: Invoke this skill when collecting a website's API interfaces.
---

# API Recon (Frontend Interface Reconnaissance)

Under an **authorized** premise, discover as completely as possible: **backend APIs** (paths, methods, parameters, response bodies), **frontend routes**, and **UI feature trigger points** (tabs, dialogs, table actions, etc.).

---

## Scope and Prohibitions (Agent must-read; crossing the line is out of bounds)

This skill **only performs API / parameter-surface reconnaissance**; it is not a vulnerability-hunting or exploitation phase.

### Task Scope

| Scope | Allowed | Prohibited |
|---|---|---|
| **Target** | Enumerate paths, methods, parameters, routes, UI trigger points | SQLi/XSS/privilege-escalation/brute-force/fuzz vulns, packet-tampering attacks, destructive operations |
| **Auth** | Hook + stub/mock to bypass the **client-side** login gate | Asking the user for or guessing usernames/passwords; attempting real login-form submission |
| **Runtime** | Hook interfaces without credentials, use mock responses to get the SPA into its post-login shell | Flows that require a real backend session to proceed |

### Credential-free dynamic analysis (Phase 3 default)

1. Use `preload.js` / `runtime_harvest.js` to **intercept and stub** bootstrap interfaces such as login, permissions, and menus;
2. Return mock bodies that are **structurally correct, carry a success business code, and may have empty data** for business query interfaces;
3. Let the frontend render post-login pages even with no backend or in a 401 environment, so it triggers more XHR/fetch/WebSocket;
4. **Empty data, blank tables, and placeholder UI are all expected**—do not switch to real login or vulnerability testing because of this.

**In one sentence**: use mocks to force frontend routes and component mounting open, and **only record outbound requests**; what the backend returns doesn't matter—what matters is **which other interfaces the frontend will call**.

### Hard process prohibitions

| Prohibited | Alternative |
|---|---|
| grep/curl/Read the main entry `index-*.js` to extract API paths before Phase 1 is complete | Run `OUTDIR/harvest_static.py` |
| Hand-writing scripts like `extract_apis.py` to replace harvest | Edit `OUTDIR/harvest_static.py` and rerun |
| Repeating the same grep/command after it has failed ≥2 times | Change strategy: read tool_logs, edit harvest, check reference |
| Skipping gates A/B and running the original `scripts/` directly | Copy to OUTDIR and adapt for the target |
| Real usernames/passwords, OTP, OAuth, and other authentication | stub/mock (see above) |
| Skipping stubs under the pretext of "getting real data" to do privilege-escalation/injection testing | Only record outbound; stays within recon scope |
| Irreversible operations such as deleting, exporting sensitive data, or bulk writes | Same applies to coverage clicks |
| Claiming to have obtained all pages and interfaces without completing runtime + dynamic enumeration | See "Definition of Done" or note the limitation |
| Claiming to know all parameters without completing the parameter trigger matrix + diff | Phase 3b matrix + Phase 5 diff |
| Inferring required/optional from a single runtime sample | Multi-sample diff, or validation rules / error-based inference |

---

## Two-Layer Model + Run Modes

| Layer | Output | Ceiling |
|---|---|---|
| **Static** (JS bundle) | Full set of endpoint paths, route draft, field candidates at assembly points | No HTTP methods; parameters need Phase 1b; misses runtime-concatenated URLs |
| **Runtime** (live session) | Method + body + response + dynamic URL + WS/SSE; multi-sample diff to complete parameters | A page must actually render to issue requests; a single sample isn't enough to settle required/optional |

| Run mode | Engine | Use for |
|---|---|---|
| **depth** | `runtime_harvest.js` (Puppeteer) | API inventory, METHOD/params/response bodies, WS/SSE, reproducible batch runs |
| **coverage** | browser + `preload.js` | Clicking tabs/dialogs/tables, deeper feature-point coverage |
| **both** | depth first, then coverage | Most complete, takes the longest |

**Parameter methodology** (no universal script): use harvest/regex for paths; use **anchor window-expansion + UI binding chain + multi-sample diff + error-based inference** for parameters (grep recipes in [reference.md](reference.md) section J).

---

## Definition of Done

recon may be claimed complete only when all of the following hold:

- [ ] **Static**: Phase 1 harvest produces `api_static.txt`, `routes.txt`, `js/`
- [ ] **Runtime**: at least one of depth or coverage; coverage/both require **working hooks + a dynamic-enumeration loop**
- [ ] **Into the shell**: visiting a business path does not land on `/login` (watch out for hash routing)
- [ ] **Parameters**: coverage/both complete the parameter trigger matrix + `param_samples.json`; Phase 5 merges `params_merged.json`
- [ ] **Depth** (if module pages are blank): Phase 4 permission-tree reconstruction and rerun, until **module-level APIs** appear (not just locale/bootstrap)
- [ ] **Delivery**: Phase 5 outputs are complete (see the Phase 5 output table); `insert_assets` writes service and endpoint assets

---

## Scripts and Gates

`scripts/` are only reference templates; **do not** run the originals directly and treat the result as final.

**Rule**: read first → adapt for the target → write into `OUTDIR` (e.g. `recon/`) → record `CHANGES.md`; if it doesn't fit, rewrite per the methodology, borrowing only the structure.

| Gate | When | Reference script → OUTDIR copy | Common mandatory changes |
|---|---|---|---|
| **A (static)** | After Phase 0, before the **first** harvest/spider run | `harvest_static.py` / `spider_mpa.py` | **The default regex runs as-is on most sites**; only when the manifest/dialect doesn't match, change the endpoint regex, webpack/Vite `publicPath`, MPA exclude/cookie |
| **B (runtime)** | After Phase 2, before running depth/coverage | `runtime_harvest.js` / `preload.js` + `config.json` | Cookie/localStorage keys, neutralize success value, stubs, login regex, api prefix, hash/history |

**Mandatory SPA order** (not interchangeable; Phase numbering takes precedence over "explore first, then script"):

| Step | Must | Prohibited |
|---|---|---|
| After Phase 0 | Next Bash = `python3 OUTDIR/harvest_static.py <URL> OUTDIR` | curl/grep/Read the main entry `index-*.js` (usually >500KB) |
| Gate A | Copy the script → make small changes as needed → **run immediately** | Manually extracting APIs first, then deciding whether to harvest |
| Before Phase 1 is complete | `wc -l` to verify output; on 404 edit harvest and retry | Hand-writing extract scripts; repeatedly grepping URLs that weren't downloaded |
| From Phase 1b on | grep only `OUTDIR/js/*.js` | Using the main bundle instead of harvest |

- ✅ Copy `harvest_static.py` → (optionally) change the regex → **run immediately**
- ❌ curl the main bundle → grep many times → write a temporary extract → harvest only at the end
- **MPA**: after Phase 0, next Bash = `python3 OUTDIR/spider_mpa.py ...`

---

## Tool and Output Constraints

| Constraint | Description |
|---|---|
| Large files | **Do not** Read/grep an `index-*.js` >100KB into context; batch-process with OUTDIR scripts |
| grep output | Must use `\| head -20` or `-m 5`; keep only a path summary in the conversation, don't paste bundle fragments |
| Verification | Use `wc -l`, `ls \| wc -l`; don't Read an entire directory |
| Initial regex probe | Optional, ≤1 time, only on a ≤50KB small chunk or HTML; the authoritative static pass is harvest |
| reference | See [reference.md](reference.md) for recipes/templates/troubleshooting; don't duplicate the full text inline |

---

## Execution Roadmap

```
Phase 0 classification + OUTDIR
  → Gate A → Phase 1 harvest (★ run immediately ★)
  → Phase 1b parameter reversing
  → Phase 2 three auth gates → config.json
  → Gate B → Phase 3 runtime + parameter matrix
  → Phase 4 permission tree (when needed) → rerun Phase 3
  → Phase 5 merged report + insert_assets to bulk-insert every discovered service and endpoint API asset; never omit a discovered asset when inserting
```

Check off in order; **do not enter the next Phase until the previous item is complete**.

1. [ ] **Phase 0**: initial SPA/MPA probe; create `OUTDIR` → [Phase 0](#phase-0--classification)
2. [ ] **Gate A + Phase 1**: copy the script → harvest **immediately** → `wc -l` to verify → [Phase 1](#phase-1--static)
3. [ ] **Phase 1b**: anchor window-expansion + binding layer → `param_candidates.json` → [Phase 1b](#phase-1b--parameter-reversing)
4. [ ] **Phase 2**: three auth gates → `config.json` → [Phase 2](#phase-2--three-auth-gates)
5. [ ] **Gate B**: adjust the runtime script → [Phase 3](#phase-3--runtime)
6. [ ] **Phase 3**: depth / coverage / both; confirm you are into the shell; parameter trigger matrix → `param_samples.json`
7. [ ] **Phase 4** (if needed): permission tree → patch stubs → rerun Phase 3 → [Phase 4](#phase-4--permission-tree-reconstruction)
8. [ ] **Phase 5**: merge outputs + report + `insert_assets` → [Phase 5](#phase-5--merge-and-report)

---

## Phase 0 — Classification

Fetch the entry HTML and **create `OUTDIR`** (don't modify the skill's own `scripts/`):

- **SPA**: empty shell + `<div id=app>` + chunks → Phase 1–5
- **MPA**: SSR + `<form>`, no endpoint bundle → after Gate A:

```bash
python3 recon/spider_mpa.py <BASE_URL> <OUTDIR> [--cookie "session=..."] [--max 300] [--depth 5] [--exclude "logout|delete|destroy"]
```

Produces `forms.txt`, `links.txt`, `api_inline.txt`. If a SPA has forms ≈ 0 → switch to Phase 1.

---

## Phase 1 — Static

Follow [Scripts and Gates](#scripts-and-gates) · [Tool and Output Constraints](#tool-and-output-constraints).

```bash
python3 recon/harvest_static.py <BASE_URL> <OUTDIR>
```

harvest: parse HTML scripts → webpack/Vite manifest → download all lazy chunks → produce `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt`.

```bash
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt
ls OUTDIR/js | wc -l
```

- chunk count vs manifest: on 404, edit harvest and retry; don't manually curl chunks one by one
- `api_static.txt` too small → loosen the endpoint regex in OUTDIR and rerun (see reference)

### Phase 1b — Parameter Reversing

Paths come from Phase 1; parameter fields need separate recon. grep rules in [Tool and Output Constraints](#tool-and-output-constraints).

**Completion bar**: for important interfaces you can answer—field name, transport location, inferred type, whether required, sample value, confidence.

#### 1b.0 — Transport Form

| Form | Where parameters live | Look at (static) first |
|---|---|---|
| REST JSON | body + query | `(params\|data\|body)\s*:\s*\{` near the path anchor |
| GraphQL | `variables` | gql templates, `$page: Int` |
| Traditional form | urlencoded | `<form>`, `FormData` |
| File upload | multipart | `FormData.append` |
| Path parameter | `/user/:id` | route table + `useParams` / `$route.params` |
| Encrypted/signed | wrapped into `sign`/`data` | Hook the encryption function's arguments (reference section D) |

Output: annotate each interface with `transport: query|json|form|graphql|encrypted`.

#### 1b.1 — Anchor Window-Expansion

Using a known path as the anchor, expand the window to find the assembly object:

```bash
grep -n '"/api/user/list"' OUTDIR/js/*.js | head -20
grep -rhoaE '.{0,120}("/api[^"]+").{0,200}' OUTDIR/js/*.js | head -20
grep -rhoaE '(params|data|body|payload)\s*:\s*\{' OUTDIR/js/*.js | head -20
```

| Wrapper layer | Parameter clue |
|---|---|
| axios instance | `data` / `params` |
| Unified request | Interceptor injects global fields |
| OpenAPI client | Generated method signature |
| React Query / SWR | The hook's second argument |
| Vue composable | composable arguments |

Type residue: `yup`/`zod`/rules, `Form.Item name=`, embedded Swagger.

→ `param_candidates.json`: `{ path, fields[], source: "static-callsite", confidence }`

#### 1b.2 — Binding Layer

```
Form field → onFinish/handleSubmit → transform → API payload
```

| Binding source | Technique |
|---|---|
| Form submit | Follow submit → transform → API |
| Table search | `getFieldsValue()` → `params` |
| Route | `:id` / `?tab=` |
| Interceptor | Global `tenantId`, pagination, sign |
| Enum select | `options` → API enum values |

In the DevTools call stack, trace upward from `fetch`/`XHR.send` to the assembly function.

#### 1b.3 — Three Assembly Questions (≠ the Phase 2 three auth gates)

| Question | What to answer |
|---|---|
| **Assembly** | Where the payload is built, transform traces |
| **Validation** | required, pattern, enum |
| **Transport** | path / query / body / multipart / headers |

The interceptor gate (Phase 2) also reads global injected fields (Authorization, `X-Tenant-Id`, sign) along the way.

#### 1b.4 — Handoff to Phase 3

Candidate fields come from the static/binding layer; **required/optional/conditional dependencies** require the Phase 3 parameter matrix + diff + Phase 5 error-based inference.

---

## Phase 2 — Three Auth Gates

grep in `OUTDIR/js/` (with `head`), and write `config.json` (recipes in reference):

| Gate | Question | Keywords |
|---|---|---|
| **Render gate** | How is "logged in" determined? | `isLogin`, `getToken`, Cookie/localStorage |
| **Interceptor gate** | What triggers a redirect to `/login`? | `response_code`, `errno`, axios interceptor |
| **Content gate** | Where do menus/permissions come from? | `menu`, `permission`, `role`, `acl`, `routes` |

Do not treat localStorage key names as credentials—confirm from the chunk/request chain.

**Exit = Gate B**: land your conclusions in `config.json` and edit `OUTDIR/runtime_harvest.js` / `preload.js`.

### Phase 2b — API Observation (optional)

Use `preload.js` in OUTDIR to confirm session key names, Authorization, and nested API URLs:

| Config | Output |
|---|---|
| `recordDetail: true` | `__API_RECON_DETAIL__` |
| `observe.xhrHeaders: true` | headers observation |
| `extractUrlsFromResponse: true` | sub-APIs within responses |
| `observe.storageReads/cookieReads: true` | backfill config |
| `neutralizeVueRouter: true` | `__API_RECON_ROUTES__` |

coverage exports each round: `__API_RECON_LOG__`, `__API_RECON_DETAIL__`, `__API_RECON_ROUTES__`, `__API_RECON_OBSERVE__`.

---

## Phase 3 — Runtime

Gate B must already be passed; follow [Scope and Prohibitions](#scope-and-prohibitions-agent-must-read-crossing-the-line-is-out-of-bounds) · the credential-free mock strategy.

In `config.json` set `"runtimeMode": "depth" | "coverage" | "both"` (template in reference).

### Hooks and stubs (shared by depth + coverage)

| Layer | Scope | Purpose |
|---|---|---|
| L1 exact | auth/permission/bootstrap stub | Pass first-screen authentication |
| L2 negative correction | all JSON responses | not-logged-in code → success |
| L3 catch-all | `/api` etc. not matched by L1 | empty success body, force the UI open |

- **depth**: fake auth + `forward` to rewrite business codes + `stubs`; traverse `routes` (hash/history); produce `runtime_api.json`
- **coverage**: inject `preload.js` at **document-start** (CDP `addScriptToEvaluateOnNewDocument` or Userscript)

Verify: `window.__API_RECON_PRELOAD__` exists; a business path does not return to `/login`.

```bash
cd recon && npm install
node runtime_harvest.js config.json
```

### 3b — coverage dynamic enumeration (mandatory)

1. Main nav/sidebar — click each item, wait 1–3s for the network
2. Tabs — `role=tab`, `.ant-tabs-tab`
3. Tables — view/edit/detail on the first row
4. Toolbar — export, filter, create (**avoid irreversible deletes**)
5. On entering each module — merge APIs/routes
6. SPA — controlled `pushState` for paths not covered by `routes.txt` (prohibited for MPA)

**Parameter trigger matrix** (mandatory): record each module once per operation type, and **diff multiple samples**:

| Operation | Parameters usually added |
|---|---|
| List first screen | pagination + default filter |
| Click search | keyword, filter |
| Advanced filter | more optional fields |
| Create/edit | the full entity |
| Bulk/export/sort | `ids[]`, `exportType`, `sortField` |

**Under stubs the outbound body/headers are still real**—trust the request. Record → `scan_raw.json`, `param_samples.json`, `api_detail.json`.

- **Vue**: `neutralizeVueRouter: true` + document-start preload
- **React**: `routes.txt` + sidebar clicks + `pushState`
- **both**: 3a depth first, then 3b coverage

---

## Phase 4 — Permission-Tree Reconstruction

**Trigger**: module pages are blank / each route has only bootstrap (e.g. locale) → the content gate hasn't been passed.

| Symptom | Meaning |
|---|---|
| Into the shell successfully | render gate + interceptor gate passed |
| Missing sidebar items / clicks go blank | stub shape or permission codes incomplete |
| Every route has the same, very few APIs | `v-if permission` not satisfied |
| `routes.txt` far smaller than the bundle | must be completed from the auth module |

```bash
grep -rhoaE '"/api[^"]*(permission|perm|role|menu|acl)[^"]*"' OUTDIR/js/*.js | sort -u | head -30
grep -rhoaE 'userRouteAuth|getResultTree|routeMap|routeLink|menuList|authList' OUTDIR/js/*.js | head -20
```

Typical chain: `role_permissions` (flat codes) + `permissions/all` (tree) → `getResultTree` → `userRouteAuth[CODE].url`.

```bash
python3 recon/extract_route_map.py recon/js recon/
python3 recon/build_perm_tree.py recon/js recon/ --config recon/config.json
```

Intermediate outputs: `route_map.json`, `userRouteAuth.json`, `permissions_tree.json`, `*_stub.json`, `perm_codes_all.txt`.

stub check: the outer `response_code` matches the interceptor gate; flat codes align with the tree; `routes` covers every link in `route_map`.

After updating `config.json`, **rerun Phase 3**. For large SPAs you can tune `waitUntil`, `routeTimeout`, `perRouteMs` (see reference sections A3/I).

---

## Phase 5 — Merge and Report

### Output Table

| File | Stage | Content |
|---|---|---|
| `js/`, `api_static.txt`, `routes.txt`, `chunkmap.txt` | 1 | static bundle and paths |
| `param_candidates.json` | 1b | static parameter-field candidates |
| `config.json` | 2 | three gates + runtime config |
| `runtime_api.json` | 3a | depth detailed recording (incl. WS/SSE) |
| `param_samples.json`, `scan_raw.json`, `api_detail.json` | 3b | multi-sample, click log, detail |
| `route_map.json` etc. | 4 | permission-tree intermediate files (if performed) |
| `params_merged.json` | 5 | merged parameter fields + confidence |
| `api_merged.txt` | 5 | `METHOD /path [params] [static\|runtime\|both]` |
| `site_map.json` | 5 | routes, APIs, params, feature points, limitations |
| **insert_assets** | 5 | write all service and endpoint assets to the asset store |

### 5b — Parameter Merge

Diff from `param_samples.json`; **no universal merge script**. Confidence rules in reference J7 (high/medium/low/pending-trigger).

### 5c — Error-Based Inference

Within the authorized scope you may send incomplete requests to read 400s (**this is parameter recon, not vulnerability testing**): `field 'x' is required`, enum errors, etc. Watch for `data` wrapping, `variables`, and pre-encryption `bizData`.

The report must note: runtimeMode, static/runtime API counts, parameter confidence, uncovered modules, and a `CHANGES.md` summary relative to the reference scripts.

Suggested `site_map.json` structure:

```json
{
  "site": "https://example.com",
  "runtimeMode": "both",
  "appType": "vue-spa",
  "routeGuardStrategy": ["nav-neutralize", "L1-auth", "L2-patch", "forward"],
  "apisFromStatic": [],
  "apisFromRuntime": [],
  "apis": [],
  "params": [{ "method": "POST", "path": "/api/user/list", "transport": "json", "fields": [] }],
  "frontendRoutes": [],
  "routesVerifiedByClick": [],
  "featuresTriggered": [],
  "limitations": ""
}
```

More fields and grep recipes in [reference.md](reference.md).

---

## General Notes

- **Framework-agnostic**: the method is the same for webpack/Vite/Angular lazy load
- **Transports**: REST/JSON, GraphQL, WebSocket, SSE; gRPC-web is out of scope
- **SSR**: client-side fetches are recordable; RSC/Server Actions are not fully enumerable
- **Blind spots**: JSVMP, WASM, strong HMAC/mTLS validation → static + note the limitation
- **Parameter blind spots**: conditional linkage, hidden params, WASM assembly → "pending-trigger" / "unreachable"
- **Static is the safety net**: when runtime is blocked, static can still enumerate endpoints

---

## Additional Resources

- Grep recipes, `config.json` template, troubleshooting, hooks, parameter-reversing section J, site_map template: **[reference.md](reference.md)**
- Reference-script paths are in the [Scripts and Gates](#scripts-and-gates) table
