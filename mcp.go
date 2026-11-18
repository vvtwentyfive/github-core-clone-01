// MCP surface: JSON-RPC 2.0 over streamable HTTP at POST /mcp.
//
// Implements the modern (2026-07-28) era cleanly: server/discover,
// initialize, tools/list, tools/call. Every tool executes against the same
// shared store as REST and GraphQL, so effects are visible across surfaces
// and ids are stable across reads.
//
// Wire contract (from the kit's mcp-client.ts / checks-mcp.ts):
//   - server/discover returns supportedVersions (a non-empty list of
//     YYYY-MM-DD strings), capabilities, and serverInfo;
//   - tools/list advertises exactly the six canonical tools with non-empty
//     descriptions and object inputSchemas, and the tools array is
//     byte-identical across calls (the result bytes are built once and
//     reused; handlers keep no shared mutable state, so concurrent calls
//     keep their own ids and arguments);
//   - tools/call answers structured content plus a text block carrying the
//     same JSON; an unknown tool answers -32602, a call missing a required
//     argument answers -32602, and a tool-level failure (unknown repo, merge
//     conflict) answers isError:true;
//   - a non-JSON body answers HTTP 400 with JSON-RPC -32700; a notification
//     (no id) answers 202 with no body; unknown methods answer -32601, never
//     a 500. Authentication (401) is enforced by the middleware.

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// mcpRevision is the protocol revision this server speaks.
const mcpRevision = "2026-07-28"

// mcpServerName and mcpServerVersion identify the server in discover and
// initialize answers.
const (
	mcpServerName    = "forge"
	mcpServerVersion = "1.0.0"
)

// rpcRequest is one JSON-RPC request. ID stays raw so it echoes verbatim
// (string and numeric ids alike).
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// mcpRPCError is a JSON-RPC error object.
type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpRPCResponse is a JSON-RPC response envelope. Result and Error are
// mutually exclusive; Result is raw JSON so prebuilt bytes pass through
// unchanged.
type mcpRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpRPCError    `json:"error,omitempty"`
}

func mcpWriteResult(w http.ResponseWriter, id json.RawMessage, result json.RawMessage) {
	WriteJSON(w, http.StatusOK, mcpRPCResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func mcpWriteError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	WriteJSON(w, http.StatusOK, mcpRPCResponse{JSONRPC: "2.0", ID: id, Error: &mcpRPCError{Code: code, Message: message}})
}

func writeParseError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}\n"))
}

// ---------------------------------------------------------------------------
// Tool catalogue (built once; the bytes are reused for every tools/list call)
// ---------------------------------------------------------------------------

type mcpToolProperty struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type mcpInputSchema struct {
	Type       string                     `json:"type"`
	Properties map[string]mcpToolProperty `json:"properties"`
	Required   []string                   `json:"required"`
}

type mcpToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema mcpInputSchema `json:"inputSchema"`
}

func mcpTools() []mcpToolDef {
	str := func(desc string) mcpToolProperty { return mcpToolProperty{Type: "string", Description: desc} }
	return []mcpToolDef{
		{
			Name:        "create_repo",
			Description: "Create a new repository owned by the authenticated user.",
			InputSchema: mcpInputSchema{
				Type: "object",
				Properties: map[string]mcpToolProperty{
					"owner":       str("The login of the repository owner."),
					"name":        str("The name of the repository to create."),
					"description": str("A description of the repository."),
					"private":     {Type: "boolean", Description: "Whether the repository is private."},
				},
				Required: []string{"name"},
			},
		},
		{
			Name:        "get_repo",
			Description: "Get a repository by owner and name.",
			InputSchema: mcpInputSchema{
				Type: "object",
				Properties: map[string]mcpToolProperty{
					"owner": str("The login of the repository owner."),
					"repo":  str("The name of the repository."),
				},
				Required: []string{"owner", "repo"},
			},
		},
		{
			Name:        "create_issue",
			Description: "Create an issue in a repository.",
			InputSchema: mcpInputSchema{
				Type: "object",
				Properties: map[string]mcpToolProperty{
					"owner": str("The login of the repository owner."),
					"repo":  str("The name of the repository."),
					"title": str("The title of the issue."),
					"body":  str("The body of the issue."),
				},
				Required: []string{"owner", "repo", "title"},
			},
		},
		{
			Name:        "list_issues",
			Description: "List issues in a repository.",
			InputSchema: mcpInputSchema{
				Type: "object",
				Properties: map[string]mcpToolProperty{
					"owner": str("The login of the repository owner."),
					"repo":  str("The name of the repository."),
					"state": str("Filter by issue state: open, closed, or all."),
				},
				Required: []string{"owner", "repo"},
			},
		},
		{
			Name:        "create_pull_request",
			Description: "Create a pull request from a head branch into a base branch.",
			InputSchema: mcpInputSchema{
				Type: "object",
				Properties: map[string]mcpToolProperty{
					"owner": str("The login of the repository owner."),
					"repo":  str("The name of the repository."),
					"title": str("The title of the pull request."),
					"body":  str("The body of the pull request."),
					"head":  str("The head branch the pull request merges from."),
					"base":  str("The base branch the pull request merges into."),
				},
				Required: []string{"owner", "repo", "title", "head", "base"},
			},
		},
		{
			Name:        "merge_pull_request",
			Description: "Squash-merge a pull request into its base branch.",
			InputSchema: mcpInputSchema{
				Type: "object",
				Properties: map[string]mcpToolProperty{
					"owner":       str("The login of the repository owner."),
					"repo":        str("The name of the repository."),
					"pull_number": {Type: "integer", Description: "The number of the pull request to merge."},
				},
				Required: []string{"owner", "repo", "pull_number"},
			},
		},
	}
}

// mcpMustJSON marshals a value, falling back to JSON null on error.
func mcpMustJSON(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return data
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

// RegisterMCP registers the MCP route on mux.
func RegisterMCP(mux *Router, s *Store) {
	// The tools/list result, built once so every call answers byte-identical
	// bytes for the tools array.
	toolsListResult := mcpMustJSON(map[string]any{"tools": mcpTools()})

	mux.Handle(func(r *http.Request, path string) bool {
		return r.Method == http.MethodPost && path == "/mcp"
	}, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
			writeParseError(w)
			return
		}
		var req rpcRequest
		if err := json.Unmarshal(trimmed, &req); err != nil {
			writeParseError(w)
			return
		}
		if len(req.ID) == 0 || string(req.ID) == "null" {
			// Notification: no response body.
			w.WriteHeader(http.StatusAccepted)
			return
		}
		switch req.Method {
		case "server/discover":
			mcpWriteResult(w, req.ID, mcpDiscoverResult())
		case "initialize":
			mcpWriteResult(w, req.ID, mcpInitializeResult(req.Params))
		case "tools/list":
			mcpWriteResult(w, req.ID, toolsListResult)
		case "tools/call":
			result, code, message := mcpCallTool(s, req.Params)
			if code != 0 {
				mcpWriteError(w, req.ID, code, message)
				return
			}
			mcpWriteResult(w, req.ID, result)
		default:
			mcpWriteError(w, req.ID, -32601, "Method not found")
		}
	})
}

func mcpServerInfo() map[string]any {
	return map[string]any{"name": mcpServerName, "version": mcpServerVersion}
}

func mcpCapabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}}
}

func mcpDiscoverResult() json.RawMessage {
	return mcpMustJSON(map[string]any{
		"supportedVersions": []string{mcpRevision},
		"capabilities":      mcpCapabilities(),
		"serverInfo":        mcpServerInfo(),
		"_meta": map[string]any{
			"io.modelcontextprotocol/serverInfo": mcpServerInfo(),
		},
	})
}

// mcpIsRevision reports whether s spells a YYYY-MM-DD protocol revision.
func mcpIsRevision(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	for i, c := range s {
		if i == 4 || i == 7 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func mcpInitializeResult(params json.RawMessage) json.RawMessage {
	version := mcpRevision
	if len(params) > 0 {
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(params, &p) == nil && mcpIsRevision(p.ProtocolVersion) {
			version = p.ProtocolVersion
		}
	}
	return mcpMustJSON(map[string]any{
		"protocolVersion": version,
		"capabilities":    mcpCapabilities(),
		"serverInfo":      mcpServerInfo(),
	})
}

// ---------------------------------------------------------------------------
// tools/call
// ---------------------------------------------------------------------------

// mcpCallParams is the params object of a tools/call request.
type mcpCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// mcpCallTool executes one tools/call. A non-zero code is a JSON-RPC error;
// otherwise result holds the tool result object (which may itself carry
// isError:true for a tool-level failure).
func mcpCallTool(s *Store, params json.RawMessage) (json.RawMessage, int, string) {
	var p mcpCallParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, -32602, "Invalid params"
		}
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}
	switch p.Name {
	case "create_repo":
		return mcpCreateRepo(s, p.Arguments)
	case "get_repo":
		return mcpGetRepo(s, p.Arguments)
	case "create_issue":
		return mcpCreateIssue(s, p.Arguments)
	case "list_issues":
		return mcpListIssues(s, p.Arguments)
	case "create_pull_request":
		return mcpCreatePullRequest(s, p.Arguments)
	case "merge_pull_request":
		return mcpMergePullRequest(s, p.Arguments)
	case "":
		return nil, -32602, "Invalid params: missing tool name"
	default:
		return nil, -32602, "Unknown tool: " + p.Name
	}
}

// mcpArgString reads the first present non-empty string argument under any of
// the given keys (canonical names first, then the suite's synonyms).
func mcpArgString(args map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := args[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s, true
			}
		}
	}
	return "", false
}

// mcpArgInt reads the first present integer argument under any of the keys,
// accepting JSON numbers and digit strings.
func mcpArgInt(args map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		if v, ok := args[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n), true
			case int:
				return n, true
			case int64:
				return int(n), true
			case json.Number:
				if i, err := n.Int64(); err == nil {
					return int(i), true
				}
			case string:
				if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
					return i, true
				}
			}
		}
	}
	return 0, false
}

// mcpArgBool reads the first present boolean argument under any of the keys.
func mcpArgBool(args map[string]any, keys ...string) (bool, bool) {
	for _, k := range keys {
		if v, ok := args[k]; ok {
			if b, ok := v.(bool); ok {
				return b, true
			}
		}
	}
	return false, false
}

// mcpMissing answers -32602 for a missing required argument.
func mcpMissing(name string) (json.RawMessage, int, string) {
	return nil, -32602, "Invalid params: missing required argument: " + name
}

// mcpToolResult wraps a payload as a tool result: structured content plus a
// text block carrying the same JSON.
func mcpToolResult(payload any) (json.RawMessage, int, string) {
	data := mcpMustJSON(payload)
	out := mcpMustJSON(map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(data)}},
		"structuredContent": json.RawMessage(data),
	})
	return out, 0, ""
}

// mcpToolErrorResult wraps a tool-level failure: isError:true with a text
// message (a JSON-RPC success carrying a failed tool outcome).
func mcpToolErrorResult(message string) (json.RawMessage, int, string) {
	out := mcpMustJSON(map[string]any{
		"content": []any{map[string]any{"type": "text", "text": message}},
		"isError": true,
	})
	return out, 0, ""
}

// mcpRepoJSON renders a repo the way REST does, with a stable numeric id.
func mcpRepoJSON(s *Store, r *Repo) map[string]any {
	s.RLock()
	description, private := r.Description, r.Private
	s.RUnlock()
	return map[string]any{
		"id":             r.ID,
		"name":           r.Name,
		"full_name":      r.Owner + "/" + r.Name,
		"owner":          map[string]any{"login": r.Owner},
		"description":    description,
		"private":        private,
		"default_branch": r.DefaultBranch,
	}
}

// mcpIssueJSON renders an issue snapshot.
func mcpIssueJSON(snap *gqlIssueSnap) map[string]any {
	return map[string]any{
		"id":     GlobalID("Issue", snap.repoID, snap.number),
		"number": snap.number,
		"title":  snap.title,
		"body":   snap.body,
		"state":  snap.state,
	}
}

// mcpPRJSON renders a pull-request snapshot.
func mcpPRJSON(snap *gqlPRSnap) map[string]any {
	return map[string]any{
		"id":     GlobalID("PullRequest", snap.repoID, snap.number),
		"number": snap.number,
		"title":  snap.title,
		"body":   snap.body,
		"state":  snap.state,
		"merged": snap.merged,
		"head":   map[string]any{"ref": snap.headRef, "sha": snap.headSHA},
		"base":   map[string]any{"ref": snap.baseRef, "sha": snap.baseSHA},
	}
}

func mcpCreateRepo(s *Store, args map[string]any) (json.RawMessage, int, string) {
	name, ok := mcpArgString(args, "name", "repo", "repository", "repository_name", "repo_name")
	if !ok {
		return mcpMissing("name")
	}
	owner, ok := mcpArgString(args, "owner", "owner_login", "org", "organization", "user", "login")
	if !ok {
		owner = ViewerLogin
	}
	description, _ := mcpArgString(args, "description", "about", "summary", "body")
	private, _ := mcpArgBool(args, "private", "is_private")
	repo, err := s.CreateRepo(owner, name, description, private)
	if err != nil {
		return mcpToolErrorResult("repository already exists")
	}
	return mcpToolResult(mcpRepoJSON(s, repo))
}

func mcpGetRepo(s *Store, args map[string]any) (json.RawMessage, int, string) {
	owner, ok := mcpArgString(args, "owner", "owner_login", "org", "organization", "user", "login")
	if !ok {
		return mcpMissing("owner")
	}
	name, ok := mcpArgString(args, "repo", "repository", "repository_name", "repo_name", "name")
	if !ok {
		return mcpMissing("repo")
	}
	repo, ok := s.GetRepo(owner, name)
	if !ok {
		return mcpToolErrorResult("repository not found")
	}
	return mcpToolResult(mcpRepoJSON(s, repo))
}

func mcpCreateIssue(s *Store, args map[string]any) (json.RawMessage, int, string) {
	owner, ok := mcpArgString(args, "owner", "owner_login", "org", "organization", "user", "login")
	if !ok {
		return mcpMissing("owner")
	}
	name, ok := mcpArgString(args, "repo", "repository", "repository_name", "repo_name")
	if !ok {
		return mcpMissing("repo")
	}
	title, ok := mcpArgString(args, "title", "issue_title", "subject")
	if !ok {
		return mcpMissing("title")
	}
	body, _ := mcpArgString(args, "body", "issue_body", "description", "content", "text")
	repo, ok := s.GetRepo(owner, name)
	if !ok {
		return mcpToolErrorResult("repository not found")
	}
	iss, err := s.CreateIssue(repo, title, body, nil)
	if err != nil {
		return mcpToolErrorResult(err.Error())
	}
	return mcpToolResult(mcpIssueJSON(gqlSnapshotIssue(s, repo, iss)))
}

func mcpListIssues(s *Store, args map[string]any) (json.RawMessage, int, string) {
	owner, ok := mcpArgString(args, "owner", "owner_login", "org", "organization", "user", "login")
	if !ok {
		return mcpMissing("owner")
	}
	name, ok := mcpArgString(args, "repo", "repository", "repository_name", "repo_name")
	if !ok {
		return mcpMissing("repo")
	}
	state, _ := mcpArgString(args, "state", "status")
	state = strings.ToLower(state)
	repo, ok := s.GetRepo(owner, name)
	if !ok {
		return mcpToolErrorResult("repository not found")
	}
	var out []any
	for _, iss := range s.ListIssues(repo) {
		snap := gqlSnapshotIssue(s, repo, iss)
		if state != "" && state != "all" && snap.state != state {
			continue
		}
		out = append(out, mcpIssueJSON(snap))
	}
	if out == nil {
		out = []any{}
	}
	return mcpToolResult(out)
}

func mcpCreatePullRequest(s *Store, args map[string]any) (json.RawMessage, int, string) {
	owner, ok := mcpArgString(args, "owner", "owner_login", "org", "organization", "user", "login")
	if !ok {
		return mcpMissing("owner")
	}
	name, ok := mcpArgString(args, "repo", "repository", "repository_name", "repo_name")
	if !ok {
		return mcpMissing("repo")
	}
	title, ok := mcpArgString(args, "title", "pr_title", "pull_request_title", "subject")
	if !ok {
		return mcpMissing("title")
	}
	head, ok := mcpArgString(args, "head", "head_ref", "head_branch", "source", "source_branch", "from_branch")
	if !ok {
		return mcpMissing("head")
	}
	base, ok := mcpArgString(args, "base", "base_ref", "base_branch", "target", "target_branch", "into_branch")
	if !ok {
		return mcpMissing("base")
	}
	body, _ := mcpArgString(args, "body", "description", "content", "text")
	repo, ok := s.GetRepo(owner, name)
	if !ok {
		return mcpToolErrorResult("repository not found")
	}
	pr, err := s.CreatePullRequest(repo, title, body, head, base)
	if err != nil {
		return mcpToolErrorResult("ref not found: " + err.Error())
	}
	return mcpToolResult(mcpPRJSON(gqlSnapshotPR(s, repo, pr)))
}

func mcpMergePullRequest(s *Store, args map[string]any) (json.RawMessage, int, string) {
	owner, ok := mcpArgString(args, "owner", "owner_login", "org", "organization", "user", "login")
	if !ok {
		return mcpMissing("owner")
	}
	name, ok := mcpArgString(args, "repo", "repository", "repository_name", "repo_name")
	if !ok {
		return mcpMissing("repo")
	}
	number, ok := mcpArgInt(args, "pull_number", "pull_request_number", "pr_number", "number", "issue_number")
	if !ok {
		return mcpMissing("pull_number")
	}
	repo, ok := s.GetRepo(owner, name)
	if !ok {
		return mcpToolErrorResult("repository not found")
	}
	pr, ok := s.GetPullRequest(repo, number)
	if !ok {
		return mcpToolErrorResult("pull request not found")
	}
	sha, err := gqlPerformSquashMerge(s, repo, pr)
	if err != nil {
		if err == errGQLMergeConflict {
			return mcpToolErrorResult("merge conflict")
		}
		return mcpToolErrorResult(err.Error())
	}
	pr, _ = s.GetPullRequest(repo, number)
	payload := mcpPRJSON(gqlSnapshotPR(s, repo, pr))
	payload["sha"] = sha
	payload["merge_commit_sha"] = sha
	payload["message"] = "Pull request successfully merged"
	return mcpToolResult(payload)
}
