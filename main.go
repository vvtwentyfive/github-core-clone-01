// Command forge is the entry's HTTP server: one in-memory store serving the
// REST v3, git smart-HTTP, GraphQL v4, and MCP surfaces.
//
// The launcher (main.ts) spawns this binary and learns its port from the
// first stdout line, "PORT=<n>". The server binds 127.0.0.1 on an ephemeral
// port and serves until SIGTERM/SIGINT.
//
// Performance shape: the hot path is deliberately thin. The middleware reads
// each request body at most once and hands the bytes on; JSON replies are
// encoded into pooled buffers with an explicit Content-Length; the runtime
// is tuned for the 2-CPU trial pod (GOMAXPROCS(2), a relaxed GC percent,
// since the heap is only a few MB).

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
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Router is a first-match routing table. Each surface module registers its
// routes with Handle; the first match wins and anything unmatched gets the
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
	for i := range rt.routes {
		if rt.routes[i].match(r, path) {
			rt.routes[i].handler(w, r)
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

// bodyKey is the request-context key for bytes the middleware already read.
type bodyKey struct{}

// middleware enforces the global wire discipline, in order:
//  1. every response gets Content-Type: application/json (handlers serving
//     git smart-HTTP binary bodies override it before writing) and a
//     non-empty deterministic X-GitHub-Request-Id;
//  2. auth: every request except GET /healthz and GET /api/v3[/] needs
//     Authorization: Bearer <MAKEFUN_SHOP_TOKEN>, else 401 JSON;
//  3. malformed JSON bodies on the REST and GraphQL surfaces get 400 JSON.
//     The MCP surface is excluded: it answers parse errors itself with the
//     JSON-RPC -32700 code. Git paths carry binary bodies and are excluded.
//
// The body is read at most once: readJSONBody slurps it, validates it, and
// stashes the bytes in the request context while restoring r.Body, so a
// handler decoding it later never re-reads the socket.
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
		if path == "/api/graphql" || path == "/api/v3" || strings.HasPrefix(path, "/api/v3/") {
			nr, ok := a.readJSONBody(r)
			if !ok {
				WriteError(w, http.StatusBadRequest, "Problems parsing JSON")
				return
			}
			r = nr
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

// readJSONBody reads a POST/PUT/PATCH body once, validates it as JSON, and
// returns a request carrying the same bytes twice over: stashed in the
// context for ReadJSON and rest.go's restBodyBytes, and as a fresh r.Body
// for handlers that decode the stream themselves. Empty bodies are valid. Any other method, or a body
// that cannot be read, passes through untouched (ok=true); a malformed
// non-empty body reports ok=false.
func (a *App) readJSONBody(r *http.Request) (*http.Request, bool) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return r, true
	}
	if r.ContentLength == 0 {
		return r, true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		return r, false
	}
	if len(bytes.TrimSpace(body)) != 0 && !json.Valid(body) {
		return r, false
	}
	// Stash under both keys: bodyKey for ReadJSON (main.go) and
	// restBodyKey for rest.go's restBodyBytes, so REST handlers decode
	// the stashed bytes with no second read and no second parse.
	ctx := context.WithValue(r.Context(), bodyKey{}, body)
	ctx = context.WithValue(ctx, restBodyKey{}, body)
	nr := r.WithContext(ctx)
	nr.Body = io.NopCloser(bytes.NewReader(body))
	return nr, true
}

// stashedBody returns the request-body bytes the middleware already read,
// if it read any.
func stashedBody(r *http.Request) ([]byte, bool) {
	body, ok := r.Context().Value(bodyKey{}).([]byte)
	return body, ok
}

// pathOf returns the decoded request path, or "/" when unusable.
func pathOf(r *http.Request) string {
	if r.URL == nil || r.URL.Path == "" {
		return "/"
	}
	return r.URL.Path
}

// jsonBufferPool recycles the scratch buffers WriteJSON encodes into, so
// the read/write hot path does not allocate a fresh buffer per reply.
// Buffers that grew absurdly large are dropped instead of pooled.
var jsonBufferPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// WriteJSON writes a JSON body with the given status. The bytes are
// identical to json.Marshal(v) plus a trailing newline: encoding/json's
// Encoder appends the newline and escapes HTML exactly like Marshal.
// Content-Length is set explicitly so the server never falls back to
// chunked framing on these small replies.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	buf := jsonBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	enc := json.NewEncoder(buf)
	if err := enc.Encode(v); err != nil {
		jsonBufferPool.Put(buf)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("{\"message\":\"Internal Server Error\"}\n"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
	if buf.Cap() <= 64<<10 {
		jsonBufferPool.Put(buf)
	}
}

type errorBody struct {
	Message string `json:"message"`
}

// WriteError writes a JSON error body: {"message": ...}.
func WriteError(w http.ResponseWriter, status int, message string) {
	WriteJSON(w, status, errorBody{Message: message})
}

// ReadJSON decodes a JSON request body. When the middleware already read the
// body, it decodes the stashed bytes (no second read); otherwise it decodes
// the live stream. The middleware has already rejected malformed bodies on
// the REST/GraphQL surfaces, so a decode error here is a shape mismatch;
// handlers answer it with 400. A stashed blank body decodes as io.EOF,
// exactly like the streaming decoder would report it.
func ReadJSON(r *http.Request, v any) error {
	if body, ok := stashedBody(r); ok {
		if len(bytes.TrimSpace(body)) == 0 {
			return io.EOF
		}
		return json.Unmarshal(body, v)
	}
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
	// Match the trial pod: 2 CPUs, and a small heap, so trade a little
	// memory for far fewer GC cycles instead of the default 100% target.
	runtime.GOMAXPROCS(2)
	debug.SetGCPercent(300)

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
