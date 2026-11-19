package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// MCP endpoint: POST /mcp, JSON-RPC 2.0 over Streamable HTTP, plain JSON
// answers (no SSE). Speaks the 2026-07-28 revision (server/discover) and
// the older initialize handshake for clients that predate discovery.

const mcpRevision = "2026-07-28"

var mcpSupportedVersions = []string{"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

var mcpServerName = "github-core-clone"
var mcpServerVersion = "1.0.0"

func mcpServerInfo() map[string]any {
	return map[string]any{"name": mcpServerName, "version": mcpServerVersion}
}

func mcpCapabilities() map[string]any {
	return map[string]any{"tools": map[string]any{}}
}

// ---------------------------------------------------------------------------
// Tool catalogue: built once, reused verbatim for every tools/list answer.
// ---------------------------------------------------------------------------

var mcpToolsOnce sync.Once
var mcpToolsCache []map[string]any

func mcpStrProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func mcpToolList() []map[string]any {
	mcpToolsOnce.Do(func() {
		mk := func(name, desc string, props map[string]any, required []string) map[string]any {
			return map[string]any{
				"name":        name,
				"description": desc,
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": props,
					"required":   required,
				},
			}
		}
		mcpToolsCache = []map[string]any{
			mk("create_repo", "Create a repository owned by the viewer.", map[string]any{
				"owner":       mcpStrProp("Login of the repository owner."),
				"name":        mcpStrProp("Name of the repository to create."),
				"description": mcpStrProp("Short description of the repository."),
				"private":     map[string]any{"type": "boolean", "description": "Whether the repository is private."},
			}, []string{"name"}),
			mk("get_repo", "Read one repository by owner and name.", map[string]any{
				"owner": mcpStrProp("Login of the repository owner."),
				"repo":  mcpStrProp("Name of the repository."),
			}, []string{"owner", "repo"}),
			mk("create_issue", "Open an issue in a repository.", map[string]any{
				"owner": mcpStrProp("Login of the repository owner."),
				"repo":  mcpStrProp("Name of the repository."),
				"title": mcpStrProp("Title of the issue."),
				"body":  mcpStrProp("Body of the issue."),
			}, []string{"owner", "repo", "title"}),
			mk("list_issues", "List the issues of a repository.", map[string]any{
				"owner": mcpStrProp("Login of the repository owner."),
				"repo":  mcpStrProp("Name of the repository."),
				"state": mcpStrProp("Filter by state: open, closed or all."),
			}, []string{"owner", "repo"}),
			mk("create_pull_request", "Open a pull request from a head branch into a base branch.", map[string]any{
				"owner": mcpStrProp("Login of the repository owner."),
				"repo":  mcpStrProp("Name of the repository."),
				"title": mcpStrProp("Title of the pull request."),
				"body":  mcpStrProp("Body of the pull request."),
				"head":  mcpStrProp("Head branch name."),
				"base":  mcpStrProp("Base branch name."),
			}, []string{"owner", "repo", "title", "head", "base"}),
			mk("merge_pull_request", "Merge an open pull request with a squash commit.", map[string]any{
				"owner":       mcpStrProp("Login of the repository owner."),
				"repo":        mcpStrProp("Name of the repository."),
				"pull_number": map[string]any{"type": "integer", "description": "Number of the pull request to merge."},
			}, []string{"owner", "repo", "pull_number"}),
			mk("get_issue", "Read one issue by owner, repository and number.", map[string]any{
				"owner":        mcpStrProp("Login of the repository owner."),
				"repo":         mcpStrProp("Name of the repository."),
				"issue_number": map[string]any{"type": "integer", "description": "Number of the issue."},
			}, []string{"owner", "repo", "issue_number"}),
			mk("list_repos", "List the repositories owned by a user.", map[string]any{
				"owner": mcpStrProp("Login of the user whose repositories to list."),
			}, []string{}),
		}
	})
	return mcpToolsCache
}

// ---------------------------------------------------------------------------
// JSON views shared with the REST shapes (same store, same ids).
// ---------------------------------------------------------------------------

func (a *App) mcpUserView() map[string]any {
	return map[string]any{"login": a.store.ViewerLogin(), "id": int64(1000), "type": "User"}
}

func (a *App) mcpRepoView(r *Repo) map[string]any {
	return map[string]any{
		"id":             r.ID,
		"name":           r.Name,
		"full_name":      r.Owner + "/" + r.Name,
		"owner":          a.mcpUserView(),
		"private":        r.Private,
		"description":    r.Description,
		"default_branch": r.DefaultBranch,
		"permissions":    map[string]any{"admin": true, "maintain": true, "push": true, "triage": true, "pull": true},
		"created_at":     r.CreatedAt,
		"updated_at":     r.UpdatedAt,
		"has_issues":     true,
		"fork":           false,
		"archived":       false,
	}
}

func (a *App) mcpIssueView(r *Repo, iss *Issue) map[string]any {
	closedAt := any(nil)
	if iss.State == "closed" {
		closedAt = iss.UpdatedAt
	}
	return map[string]any{
		"id":         iss.ID,
		"number":     iss.Number,
		"title":      iss.Title,
		"body":       iss.Body,
		"state":      iss.State,
		"labels":     []any{},
		"user":       a.mcpUserView(),
		"comments":   iss.Comments,
		"created_at": iss.CreatedAt,
		"updated_at": iss.UpdatedAt,
		"closed_at":  closedAt,
	}
}

func (a *App) mcpPullView(r *Repo, pr *Pull) map[string]any {
	headSHA, _ := a.store.BranchTip(r, pr.Head)
	baseSHA, _ := a.store.BranchTip(r, pr.Base)
	mergedAt := any(nil)
	mergeSHA := any(nil)
	if pr.Merged {
		mergedAt = pr.MergedAt
		mergeSHA = pr.MergeSHA
	}
	return map[string]any{
		"id":               pr.ID,
		"number":           pr.Number,
		"title":            pr.Title,
		"body":             pr.Body,
		"state":            pr.State,
		"head":             map[string]any{"ref": pr.Head, "sha": headSHA, "label": r.Owner + ":" + pr.Head},
		"base":             map[string]any{"ref": pr.Base, "sha": baseSHA, "label": r.Owner + ":" + pr.Base},
		"merged":           pr.Merged,
		"merged_at":        mergedAt,
		"merge_commit_sha": mergeSHA,
		"user":             a.mcpUserView(),
		"created_at":       pr.CreatedAt,
		"updated_at":       pr.UpdatedAt,
	}
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

func mcpArgStr(args map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := args[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func mcpArgBool(args map[string]any, key string) bool {
	if b, ok := args[key].(bool); ok {
		return b
	}
	return false
}

func mcpArgNum(args map[string]any, keys ...string) (int64, bool) {
	for _, k := range keys {
		switch v := args[k].(type) {
		case float64:
			return int64(v), true
		case int64:
			return v, true
		case string:
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return n, true
			}
		case json.Number:
			if n, err := v.Int64(); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// splitOwnerRepo resolves owner/repo from the arguments, accepting a
// full_name of the form "owner/repo" as a fallback.
func mcpOwnerRepo(a *App, args map[string]any) (string, string) {
	owner := mcpArgStr(args, "owner", "owner_login")
	repo := mcpArgStr(args, "repo", "repository", "repository_name", "repo_name")
	if (owner == "" || repo == "") && mcpArgStr(args, "full_name") != "" {
		parts := strings.SplitN(mcpArgStr(args, "full_name"), "/", 2)
		if len(parts) == 2 {
			if owner == "" {
				owner = parts[0]
			}
			if repo == "" {
				repo = parts[1]
			}
		}
	}
	if owner == "" {
		owner = a.store.ViewerLogin()
	}
	return owner, repo
}

func mcpTextResult(obj any) map[string]any {
	raw, _ := json.Marshal(obj)
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(raw)}},
		"structuredContent": obj,
	}
}

func mcpErrorResult(msg string) map[string]any {
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": msg}},
		"isError": true,
	}
}

// ---------------------------------------------------------------------------
// Tool dispatch
// ---------------------------------------------------------------------------

func mcpNormalize(name string) string {
	var sb strings.Builder
	for _, ch := range strings.ToLower(name) {
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
			sb.WriteRune(ch)
		}
	}
	return sb.String()
}

var mcpCanonicalTools = []string{
	"create_repo", "get_repo", "create_issue", "list_issues",
	"create_pull_request", "merge_pull_request", "get_issue", "list_repos",
}

func mcpMatchTool(name string) string {
	norm := mcpNormalize(name)
	for _, canon := range mcpCanonicalTools {
		if norm == mcpNormalize(canon) {
			return canon
		}
	}
	for _, canon := range mcpCanonicalTools {
		want := mcpNormalize(canon)
		if len(norm) > len(want) && strings.HasSuffix(norm, want) {
			return canon
		}
	}
	return ""
}

func (a *App) mcpCallTool(name string, args map[string]any) (map[string]any, *mcpRPCError) {
	canon := mcpMatchTool(name)
	if canon == "" {
		return nil, &mcpRPCError{code: -32601, message: "Unknown tool: " + name}
	}
	missing := func(fields ...string) (map[string]any, *mcpRPCError) {
		for _, f := range fields {
			if mcpArgStr(args, f) == "" {
				return mcpErrorResult("Missing required argument: " + f), nil
			}
		}
		return nil, nil
	}
	switch canon {
	case "create_repo":
		if res, rpcErr := missing("name"); res != nil || rpcErr != nil {
			return res, rpcErr
		}
		owner := mcpArgStr(args, "owner", "owner_login")
		if owner == "" {
			owner = a.store.ViewerLogin()
		}
		r, err := a.store.CreateRepo(owner, mcpArgStr(args, "name"), mcpArgStr(args, "description"), mcpArgBool(args, "private"))
		if err != nil {
			return mcpErrorResult("create_repo: " + err.Error()), nil
		}
		return mcpTextResult(a.mcpRepoView(r)), nil
	case "get_repo":
		if res, rpcErr := missing("owner", "repo"); res != nil || rpcErr != nil {
			return res, rpcErr
		}
		owner, repo := mcpOwnerRepo(a, args)
		r := a.store.GetRepo(owner, repo)
		if r == nil {
			return mcpErrorResult("Repository not found: " + owner + "/" + repo), nil
		}
		return mcpTextResult(a.mcpRepoView(r)), nil
	case "create_issue":
		if res, rpcErr := missing("owner", "repo", "title"); res != nil || rpcErr != nil {
			return res, rpcErr
		}
		owner, repo := mcpOwnerRepo(a, args)
		r := a.store.GetRepo(owner, repo)
		if r == nil {
			return mcpErrorResult("Repository not found: " + owner + "/" + repo), nil
		}
		iss, err := a.store.CreateIssue(r, mcpArgStr(args, "title"), mcpArgStr(args, "body"), nil)
		if err != nil {
			return mcpErrorResult("create_issue: " + err.Error()), nil
		}
		return mcpTextResult(a.mcpIssueView(r, iss)), nil
	case "list_issues":
		if res, rpcErr := missing("owner", "repo"); res != nil || rpcErr != nil {
			return res, rpcErr
		}
		owner, repo := mcpOwnerRepo(a, args)
		r := a.store.GetRepo(owner, repo)
		if r == nil {
			return mcpErrorResult("Repository not found: " + owner + "/" + repo), nil
		}
		state := strings.ToLower(mcpArgStr(args, "state"))
		if state == "all" {
			state = ""
		}
		issues := a.store.ListIssues(r, state)
		views := make([]any, 0, len(issues))
		for _, iss := range issues {
			views = append(views, a.mcpIssueView(r, iss))
		}
		return mcpTextResult(views), nil
	case "create_pull_request":
		if res, rpcErr := missing("owner", "repo", "title", "head", "base"); res != nil || rpcErr != nil {
			return res, rpcErr
		}
		owner, repo := mcpOwnerRepo(a, args)
		r := a.store.GetRepo(owner, repo)
		if r == nil {
			return mcpErrorResult("Repository not found: " + owner + "/" + repo), nil
		}
		pr, err := a.store.CreatePull(r, mcpArgStr(args, "title"), mcpArgStr(args, "head"), mcpArgStr(args, "base"), mcpArgStr(args, "body"))
		if err != nil {
			return mcpErrorResult("create_pull_request: " + err.Error()), nil
		}
		return mcpTextResult(a.mcpPullView(r, pr)), nil
	case "merge_pull_request":
		if res, rpcErr := missing("owner", "repo"); res != nil || rpcErr != nil {
			return res, rpcErr
		}
		num, ok := mcpArgNum(args, "pull_number", "pull_request_number", "pr_number", "number")
		if !ok || num <= 0 {
			return mcpErrorResult("Missing required argument: pull_number"), nil
		}
		owner, repo := mcpOwnerRepo(a, args)
		r := a.store.GetRepo(owner, repo)
		if r == nil {
			return mcpErrorResult("Repository not found: " + owner + "/" + repo), nil
		}
		sha, err := a.store.MergePull(r, int(num))
		if err != nil {
			return mcpErrorResult("merge_pull_request: " + err.Error()), nil
		}
		pr := a.store.GetPull(r, int(num))
		view := a.mcpPullView(r, pr)
		view["sha"] = sha
		return mcpTextResult(view), nil
	case "get_issue":
		if res, rpcErr := missing("owner", "repo"); res != nil || rpcErr != nil {
			return res, rpcErr
		}
		num, ok := mcpArgNum(args, "issue_number", "number")
		if !ok || num <= 0 {
			return mcpErrorResult("Missing required argument: issue_number"), nil
		}
		owner, repo := mcpOwnerRepo(a, args)
		r := a.store.GetRepo(owner, repo)
		if r == nil {
			return mcpErrorResult("Repository not found: " + owner + "/" + repo), nil
		}
		iss := a.store.GetIssue(r, int(num))
		if iss == nil {
			return mcpErrorResult("Issue not found"), nil
		}
		return mcpTextResult(a.mcpIssueView(r, iss)), nil
	case "list_repos":
		owner := mcpArgStr(args, "owner", "owner_login")
		if owner == "" {
			owner = a.store.ViewerLogin()
		}
		repos := a.store.ListRepos(owner)
		views := make([]any, 0, len(repos))
		for _, r := range repos {
			views = append(views, a.mcpRepoView(r))
		}
		return mcpTextResult(views), nil
	}
	return nil, &mcpRPCError{code: -32601, message: "Unknown tool: " + name}
}

// ---------------------------------------------------------------------------
// JSON-RPC plumbing
// ---------------------------------------------------------------------------

type mcpRPCError struct {
	code    int
	message string
}

func (a *App) mcpReply(w http.ResponseWriter, id any, result any, rpcErr *mcpRPCError) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		resp["error"] = map[string]any{"code": rpcErr.code, "message": rpcErr.message}
	} else {
		resp["result"] = result
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (a *App) handleMCP(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	raw := BodyBytes(r)
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed == nil {
		WriteJSON(w, http.StatusBadRequest, map[string]any{
			"jsonrpc": "2.0",
			"id":      nil,
			"error":   map[string]any{"code": -32700, "message": "Parse error"},
		})
		return
	}
	method, _ := parsed["method"].(string)
	params, _ := parsed["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	_, hasID := parsed["id"]
	id := parsed["id"]
	if method == "" {
		a.mcpReply(w, id, nil, &mcpRPCError{code: -32600, message: "Invalid Request: missing method"})
		return
	}
	if strings.HasPrefix(method, "notifications/") || !hasID {
		w.WriteHeader(http.StatusOK)
		return
	}
	switch method {
	case "server/discover":
		a.mcpReply(w, id, map[string]any{
			"resultType":        "discover",
			"supportedVersions": mcpSupportedVersions,
			"capabilities":      mcpCapabilities(),
			"instructions":      "GitHub core clone: repositories, issues and pull requests over MCP tools.",
			"serverInfo":        mcpServerInfo(),
			"_meta": map[string]any{
				"io.modelcontextprotocol/serverInfo": mcpServerInfo(),
			},
		}, nil)
	case "initialize":
		version := mcpRevision
		if offered, ok := params["protocolVersion"].(string); ok && offered != "" {
			version = offered
			supported := false
			for _, v := range mcpSupportedVersions {
				if v == offered {
					supported = true
					break
				}
			}
			if !supported {
				a.mcpReply(w, id, nil, &mcpRPCError{code: -32602, message: "Unsupported protocol version: " + offered})
				return
			}
		}
		w.Header().Set("Mcp-Session-Id", "mcp-session-1")
		a.mcpReply(w, id, map[string]any{
			"protocolVersion": version,
			"capabilities":    mcpCapabilities(),
			"serverInfo":      mcpServerInfo(),
		}, nil)
	case "ping":
		a.mcpReply(w, id, map[string]any{}, nil)
	case "tools/list":
		a.mcpReply(w, id, map[string]any{"tools": mcpToolList()}, nil)
	case "tools/call":
		name, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]any)
		if args == nil {
			args = map[string]any{}
		}
		result, rpcErr := a.mcpCallTool(name, args)
		a.mcpReply(w, id, result, rpcErr)
	default:
		a.mcpReply(w, id, nil, &mcpRPCError{code: -32601, message: "Method not found: " + method})
	}
}
