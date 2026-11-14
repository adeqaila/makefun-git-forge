# GitHub-compatible git forge — make.fun bounty `github-core-clone-01`

A standalone GitHub-compatible git forge: one process, Node 22 stdlib only, no
`git` binary, no install, no external network. Serves git smart HTTP
(upload-pack v2, receive-pack v0), REST v3, GraphQL and MCP from one
in-memory store.

## Files

| File | What it is |
| --- | --- |
| `main.ts` | Entry / env lifecycle: binds an ephemeral port, `POST {"port"}` to `$MAKEFUN_ENV_URL/register`, long-polls `GET $MAKEFUN_ENV_URL/done`, exits 0. Local mode (no `MAKEFUN_ENV_URL`): serves on `$PORT` or an ephemeral port and keeps running. |
| `app.ts` | The whole forge (~160 KB, single file): object store + packfile codec, git smart HTTP, REST v3, GraphQL, MCP. |
| `package.json`, `tsconfig.json`, `LICENSE` | From the kit starter (`"type": "module"`). |
| `kit/` | The competition kit (reference material, not part of the entry). |
| `PROGRESS.md` | Build notes and test log. |

## Run locally

```sh
MAKEFUN_SHOP_TOKEN=test-token PORT=18080 node --experimental-strip-types main.ts
```

Then grade it with the kit's local runner (no docker needed):

```sh
node --experimental-strip-types kit/sdk/run.ts --url http://127.0.0.1:18080 --token test-token --json
node --experimental-strip-types kit/sdk/run.ts --url http://127.0.0.1:18080 --token test-token --perf --json
```

**Use a fresh server per run.** Checks create repos/issues with fixed names, so a
second run against the same server fails on duplicate names — that is state
pollution, not a forge bug.

## Score (local, fresh server, 2026-11-14)

| | |
| --- | --- |
| Conformance | **120/120** — git 30/30, repos 15/15, issues 15/15, pulls 20/20, protocol 5/5, graphql 20/20, mcp 15/15 |
| Feature / agent / perf | **600 / 200 / 186 → 986 / 1000** |
| Perf p50 | push ~510 ms, clone ~100 ms, read ~750 ms, write ~90 ms; `perf_p50_us` ~244k (reference ≈ 806k) |

Perf points vary a few points run to run (shared CPU); feature/agent are stable
at 120/120.

## Manual smoke test (real `git` CLI)

```sh
curl -s -X POST -H "Authorization: Bearer test-token" \
  -d '{"name":"manual-smoke"}' http://127.0.0.1:18080/api/v3/user/repos
git -c http.extraHeader="Authorization: Bearer test-token" \
  clone http://127.0.0.1:18080/adaiversen/manual-smoke.git
# commit, push (fast-forward ok, non-fast-forward rejected with ng), clone back
```

Verified 2026-11-14 with git 2.43.0: empty clone lands on `main`, push works,
non-FF push is rejected, clone-back content is byte-identical.

## Design notes

- **Auth:** `Authorization: Bearer $MAKEFUN_SHOP_TOKEN`; missing/wrong = 401.
  When the env token is unset (local mode), any non-empty Bearer is accepted.
- **Viewer/owner:** the scenario viewer is `adaiversen` (fixed scenario seed).
  A repo's owner is the creator's login; the same name under another owner is
  404, never 403. An owner match confirms the repo.
- **Determinism:** no wall-clock time in state — timestamps and ids come from a
  monotonic sequence counter (epoch 1700000000 + seq). Two fresh servers given
  the same operation sequence return byte-identical bodies (verified).
- **Git:** own object store (SHA-1, zlib), packfile parsing incl. OFS/REF
  deltas and thin packs, pack generation (plain objects). Push is fast-forward
  only, per-ref `ok`/`ng`; delete-only pushes carry no pack. Fetch subtracts
  objects the client already holds (full closure for complete haves, commit +
  tree only for shallow boundaries) and reports `shallow`/`unshallow`.
- **v2 fetch sections are sent only when non-empty** (acknowledgments only if
  haves were sent, shallow-info only with shallow/unshallow lines) — real git
  dies with `expected 'packfile'` if an empty section header is sent.
- **Receive-pack report** is pkt-lined inside sideband band 1 (real git's
  reader parses pkt-lines out of the demuxed band-1 bytes).
- **REST:** issues and PRs share one per-repo number sequence; duplicate repo
  name = 422 `already exists`; duplicate open PR (same head+base) = 422;
  merge is a squash commit onto the default branch with 3-way conflict
  detection; stale contents sha = 409.
- **GraphQL:** small recursive-descent parser (operations, aliases, variables,
  fragments, `__type`/`__schema` introspection). Global ids are opaque base64
  (`R:`, `I:`, `P:`, `C:` prefixes).
- **MCP:** Streamable HTTP, revision `2026-07-28` via `server/discover`
  (+ legacy `initialize` fallback). Exactly 6 tools, deterministic
  `tools/list` bytes.
- **Performance:** fetch-pack cache (pack + selection), precomputed object
  ids in pack sort, cached serialized single-issue JSON for the read workload.

## What is NOT done

- **Not submitted.** Submission needs the user: a GitHub account (or Solana
  wallet for the USDC prize) plus the transcripts bundle. Nothing was created
  and no credentials were used.
- The kit's `grade-local --driver docker` path was not used (no docker here);
  grading used `kit/sdk/run.ts` instead, which runs the same 120 sealed
  checks plus the bench.
