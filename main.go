// Command forge is the entry's HTTP server: one in-memory store serving the
// REST v3, git smart-HTTP, GraphQL v4, and MCP surfaces.
//
// The launcher (main.ts) spawns this binary and learns its port from the
// first stdout line, "PORT=<n>". The server binds 127.0.0.1 on an ephemeral
// port and serves until SIGTERM/SIGINT.

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
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Router is a first-match routing table. Module files register their routes
// with Handle via their RegisterXxx functions; unmatched requests get the
// JSON 404 below.
type Router struct {
	routes []routeEntry
}

type routeEntry struct {
	match   func(r *http.Request, path string) bool
	handler http.HandlerFunc
}

// Handle appends a route. Earlier routes win.
func (rt *Router) Handle(match func(r *http.Request, path string) bool, handler http.HandlerFunc) {
	rt.routes = append(rt.routes, routeEntry{match: match, handler: handler})
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := pathOf(r)
	for _, e := range rt.routes {
		if e.match(r, path) {
			e.handler(w, r)
			return
		}
	}
	WriteError(w, http.StatusNotFound, "Not Found")
}

// App carries the store and the expected bearer token for the middleware.
type App struct {
	store *Store
	token string
}

// middleware enforces the global wire discipline, in order:
//  1. every response gets Content-Type: application/json (handlers serving
//     git smart-HTTP binary bodies override it before writing) and a
//     non-empty deterministic X-GitHub-Request-Id;
//  2. auth: every request except GET /healthz and GET /api/v3[/] needs
//     Authorization: Bearer <MAKEFUN_SHOP_TOKEN>, else 401 JSON;
//  3. malformed JSON bodies on the REST and GraphQL surfaces get 400 JSON.
//     The MCP surface is excluded: it answers parse errors itself with the
//     JSON-RPC -32700 code. Git paths carry binary bodies and are excluded.
func (a *App) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-GitHub-Request-Id", a.store.NextRequestID())
		w.Header().Set("Content-Type", "application/json")
		path := pathOf(r)
		authExempt := r.Method == http.MethodGet &&
			(path == "/healthz" || path == "/api/v3" || path == "/api/v3/")
		if !authExempt && !a.authorized(r) {
			WriteError(w, http.StatusUnauthorized, "Bad credentials")
			return
		}
		if (path == "/api/graphql" || path == "/api/v3" || strings.HasPrefix(path, "/api/v3/")) &&
			!a.validJSONBody(r) {
			WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) authorized(r *http.Request) bool {
	if a.token == "" {
		return true // no token configured (local runs without the env var)
	}
	return r.Header.Get("Authorization") == "Bearer "+a.token
}

// validJSONBody checks that a POST/PUT/PATCH body is well-formed JSON and
// restores the body for the handler. Empty bodies are valid.
func (a *App) validJSONBody(r *http.Request) bool {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return true
	}
	if r.ContentLength == 0 {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 {
		return true
	}
	return json.Valid(body)
}

// pathOf returns the decoded request path, or "/" when unusable.
func pathOf(r *http.Request) string {
	if r.URL == nil || r.URL.Path == "" {
		return "/"
	}
	return r.URL.Path
}

// WriteJSON writes a JSON body with the given status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\"message\":\"Internal Server Error\"}\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}

type errorBody struct {
	Message string `json:"message"`
}

// WriteError writes a JSON error body: {"message": ...}.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, errorBody{Message: message})
}

// ReadJSON decodes a JSON request body. The middleware has already rejected
// malformed bodies on the REST/GraphQL surfaces, so a decode error here is
// a shape mismatch; handlers answer it with 400.
func ReadJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

type apiRoot struct {
	CurrentUserURL string `json:"current_user_url"`
	RateLimitURL   string `json:"rate_limit_url"`
}

var apiRootBody = apiRoot{
	CurrentUserURL: "/api/v3/user",
	RateLimitURL:   "/api/v3/rate_limit",
}

func main() {
	store := NewStore()
	app := &App{store: store, token: os.Getenv("MAKEFUN_SHOP_TOKEN")}

	mux := &Router{}

	// Boot probe: no auth, 200 {"ok":true}.
	mux.Handle(func(r *http.Request, path string) bool {
		return r.Method == http.MethodGet && path == "/healthz"
	}, func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	// API root: 200 + scopes header.
	mux.Handle(func(r *http.Request, path string) bool {
		return r.Method == http.MethodGet && (path == "/api/v3" || path == "/api/v3/")
	}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oauth-Scopes", "repo, read:org")
		WriteJSON(w, http.StatusOK, apiRootBody)
	})

	RegisterREST(mux, store)
	RegisterGit(mux, store)
	RegisterGraphQL(mux, store)
	RegisterMCP(mux, store)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	// FIRST stdout line: the launcher reads this to learn the port.
	fmt.Printf("PORT=%d\n", port)

	srv := &http.Server{
		Handler:           app.middleware(mux),
		ReadHeaderTimeout: 30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}
