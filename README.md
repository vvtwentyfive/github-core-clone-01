# github-core-clone-01 — a GitHub-compatible git forge

An entry for the [make.fun bounty github-core-clone-01](https://make.fun/bounty/github-core-clone-01):
a single-process server implementing the GitHub-compatible surface the
grading suite drives — REST v3, git smart HTTP, GraphQL v4, and MCP — over
one shared in-memory store. No UI, no database, no network beyond the suite.

## Architecture

```
main.ts        thin launcher (Node 22, type-stripped, zero dependencies):
               copies the vendored binary to /tmp, spawns it, reads its
               PORT=<n> startup line, registers with the env, polls /done,
               shuts the child down, exits 0.
forge-bin      statically linked Linux amd64 Go binary (built from the
               committed Go sources in this repo; CGO_ENABLED=0).
store.go       the shared store: repos, git objects, refs, issues, pull
               requests, labels. RWMutex-guarded; deterministic outputs
               (logical clock from MAKEFUN_TRIAL_NOW/MAKEFUN_TRIAL_SEED,
               monotonic request ids, sequence-based ordering).
main.go        HTTP entrypoint: ephemeral 127.0.0.1:0 bind, PORT= first
               stdout line, routing table, global middleware (JSON content
               type, X-GitHub-Request-Id, bearer auth, malformed-JSON 400,
               JSON 404), /healthz and the API root.
rest.go        REST v3 routes.
git.go         git smart-HTTP routes (info/refs, upload-pack, receive-pack).
pack.go        pkt-line framing + packfile helpers.
graphql.go     POST /api/graphql.
mcp.go         POST /mcp (JSON-RPC 2.0 streamable HTTP).
```

All four surfaces share the one `Store`, so a repo created over REST is
clonable over git, readable over GraphQL, and visible over MCP with stable
ids. The fixed suite constants (viewer `adaiversen`, id 1000, default branch
`main`) live in `store.go`.

## Build

```sh
./build.sh
```

Builds the static binary with `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`,
`-trimpath -ldflags "-s -w"`, to `./forge-bin`, and fails if the binary
exceeds 8 MiB or the tree exceeds 16 MiB (the competition's size caps).
Go 1.25, standard library only, no external dependencies.

## Run locally

```sh
MAKEFUN_SHOP_TOKEN=test-token ./forge-bin   # prints PORT=<n>, serves until SIGTERM/SIGINT
```

## Test locally

```sh
./test-local.sh
```

Builds, starts the binary, and runs the kit's conformance suite
(`sdk/run.ts`) against it, printing the score columns.

## Status

Complete: all four surfaces are implemented over the shared store — REST v3
(`rest.go`), git smart HTTP (`git.go`, `pack.go`), GraphQL v4 (`graphql.go`),
and MCP (`mcp.go`). Verified locally against the kit conformance suite:
120/120 checks passing, including `--perf` runs (perf 173–174/200).

## License

MIT — see [LICENSE](LICENSE).
