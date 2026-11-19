package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// App is the forge server: one store, the bearer token that doubles as the
// viewer login, and the global request-id counter.
type App struct {
	store *Store
	token string
	reqID atomic.Uint64
}

// NewApp builds a server around an existing store.
func NewApp(store *Store) *App {
	a := &App{store: store}
	if store != nil {
		a.token = store.Token()
	}
	return a
}

// bodyCtxKey is the request-context key under which ServeHTTP stashes the
// request body bytes it read once.
type bodyCtxKey string

const stashedBodyKey bodyCtxKey = "forge-body"

// ServeHTTP is the whole front door: it stamps the request id, reads the
// request body exactly once and stashes it, then routes.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := a.reqID.Add(1)
	w.Header().Set("X-GitHub-Request-Id", "req-"+strconv.FormatUint(n, 10))
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}
	r = r.WithContext(context.WithValue(r.Context(), stashedBodyKey, body))
	a.route(w, r)
}

// route matches method + path. Unknown paths and wrong methods are 404 JSON
// here, before any auth check, so an unauthenticated unknown path still
// answers 404. Auth itself lives inside each handler group.
func (a *App) route(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	if method == http.MethodGet && path == "/healthz" {
		WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	if method == http.MethodGet && (path == "/api/v3" || path == "/api/v3/") {
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		WriteJSON(w, http.StatusOK, map[string]string{
			"current_user_url": "/api/v3/user",
			"rate_limit_url":   "/api/v3/rate_limit",
		})
		return
	}
	if method == http.MethodPost && path == "/api/graphql" {
		a.handleGraphQL(w, r)
		return
	}
	if method == http.MethodPost && path == "/mcp" {
		a.handleMCP(w, r)
		return
	}
	if strings.HasPrefix(path, "/api/v3/") {
		if a.restRouteOK(method, path) {
			a.handleREST(w, r)
			return
		}
		WriteError(w, http.StatusNotFound, "Not Found")
		return
	}
	if owner, repo, tail, ok := splitGitPath(path); ok {
		switch {
		case method == http.MethodGet && tail == "info/refs":
			a.handleInfoRefs(w, r, owner, repo)
		case method == http.MethodPost && tail == "git-upload-pack":
			a.handleUploadPack(w, r, owner, repo)
		case method == http.MethodPost && tail == "git-receive-pack":
			a.handleReceivePack(w, r, owner, repo)
		default:
			WriteError(w, http.StatusNotFound, "Not Found")
		}
		return
	}
	WriteError(w, http.StatusNotFound, "Not Found")
}

// splitGitPath pulls /{owner}/{repo}.git/{tail} apart. It reports false for
// anything that is not shaped like a git smart-HTTP path.
func splitGitPath(path string) (owner, repo, tail string, ok bool) {
	rest := strings.TrimPrefix(path, "/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) != 3 || parts[0] == "" {
		return "", "", "", false
	}
	if !strings.HasSuffix(parts[1], ".git") {
		return "", "", "", false
	}
	repo = strings.TrimSuffix(parts[1], ".git")
	if repo == "" {
		return "", "", "", false
	}
	return parts[0], repo, parts[2], true
}

// restRouteOK validates a REST method + path shape against the route table.
// It knows shapes only; the resource handlers behind handleREST own the rest.
func (a *App) restRouteOK(method, path string) bool {
	if path == "/api/v3/meta" {
		return method == http.MethodGet
	}
	if path == "/api/v3/user" {
		return method == http.MethodGet
	}
	if path == "/api/v3/user/repos" {
		return method == http.MethodGet || method == http.MethodPost
	}
	rest, found := strings.CutPrefix(path, "/api/v3/repos/")
	if !found {
		return false
	}
	segs := strings.Split(rest, "/")
	if len(segs) < 2 || segs[0] == "" || segs[1] == "" {
		return false
	}
	tail := segs[2:]
	switch len(tail) {
	case 0:
		return method == http.MethodGet || method == http.MethodPatch || method == http.MethodDelete
	case 1:
		switch tail[0] {
		case "labels", "issues", "pulls":
			return method == http.MethodGet || method == http.MethodPost
		case "branches", "commits":
			return method == http.MethodGet
		}
		return false
	case 2:
		switch tail[0] {
		case "issues":
			return isDigits(tail[1]) && (method == http.MethodGet || method == http.MethodPatch)
		case "pulls":
			return isDigits(tail[1]) && method == http.MethodGet
		case "contents":
			return tail[1] != "" && (method == http.MethodGet || method == http.MethodPut || method == http.MethodDelete)
		case "branches":
			return tail[1] != "" && method == http.MethodGet
		case "git":
			return tail[1] == "refs" && (method == http.MethodGet || method == http.MethodPost)
		}
		return false
	case 3:
		if tail[0] == "contents" {
			return method == http.MethodGet || method == http.MethodPut || method == http.MethodDelete
		}
		if tail[0] == "issues" && isDigits(tail[1]) && tail[2] == "comments" {
			return method == http.MethodGet || method == http.MethodPost
		}
		if tail[0] == "pulls" && isDigits(tail[1]) && tail[2] == "files" {
			return method == http.MethodGet
		}
		if tail[0] == "pulls" && isDigits(tail[1]) && tail[2] == "merge" {
			return method == http.MethodPut
		}
		return false
	case 4:
		if tail[0] == "git" && tail[1] == "refs" && tail[2] == "heads" && tail[3] != "" {
			return method == http.MethodGet
		}
		return false
	default:
		if tail[0] == "contents" {
			return method == http.MethodGet || method == http.MethodPut || method == http.MethodDelete
		}
		if tail[0] == "pulls" && len(tail) == 3 && isDigits(tail[1]) && tail[2] == "merge" {
			return method == http.MethodPut
		}
		return false
	}
}

// isDigits reports whether s is a non-empty run of ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// jsonBufPool hands out reusable staging buffers for JSON replies so the
// common path allocates no fresh buffer per request.
var jsonBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

// fallbackBody is the static reply when a value cannot be marshalled at all.
const fallbackBody = `{"message":"internal error"}`

// WriteJSON marshals v into a pooled buffer and writes it with an explicit
// Content-Length and Content-Type application/json, compact, no trailing
// newline.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	buf := jsonBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer jsonBufPool.Put(buf)
	if err := json.NewEncoder(buf).Encode(v); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(fallbackBody)))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fallbackBody))
		return
	}
	payload := buf.Bytes()
	if n := len(payload); n > 0 && payload[n-1] == '\n' {
		payload = payload[:n-1]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

// WriteError writes {"message": msg} at the given status.
func WriteError(w http.ResponseWriter, status int, msg string) {
	WriteJSON(w, status, map[string]string{"message": msg})
}

// requireAuth checks Authorization: Bearer <token>. On failure it writes
// 401 {"message":"Bad credentials"} and reports false; callers return.
func (a *App) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "Bearer "+a.token {
		WriteError(w, http.StatusUnauthorized, "Bad credentials")
		return false
	}
	return true
}

// BodyBytes returns the request body bytes ServeHTTP read once and stashed
// in the request context, or nil when there was no body.
func BodyBytes(r *http.Request) []byte {
	if r == nil {
		return nil
	}
	if b, ok := r.Context().Value(stashedBodyKey).([]byte); ok {
		return b
	}
	return nil
}

func main() {
	runtime.GOMAXPROCS(2)
	debug.SetGCPercent(300)
	token := os.Getenv("MAKEFUN_SHOP_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "MAKEFUN_SHOP_TOKEN is not set")
		os.Exit(1)
	}
	store := NewStore(token)
	app := NewApp(store)
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	fmt.Printf("PORT=%d\n", port)
	if err := http.Serve(ln, app); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}
