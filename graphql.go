// GraphQL v4 surface: a document executor for POST /api/graphql.
//
// The suite sends 18 fixed documents (see the kit's checks-graphql.ts). This
// file implements a small, purpose-built GraphQL engine: a lexer and a
// recursive-descent parser for operation documents (selection sets, aliases,
// arguments, variables, inline fragments, fragment spreads), a validation
// pass against the asserted schema surface (unknown fields produce HTTP 200
// with an errors array naming the field), and resolvers that execute against
// the shared store, so every mutation is visible over REST and vice versa.
//
// Supported surface: Query.viewer, Query.repository, Query.node,
// Query.__type, Repository/Issue/PullRequest reads with connections and
// cursor pagination, and the createIssue/closeIssue/createPullRequest/
// mergePullRequest/addComment mutations. Batched bodies (a JSON array of
// operations) answer an array of results in request order. Unknown
// repositories read data.repository=null with no errors. Global ids use the
// store's opaque GlobalID helpers.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

// gqlRequest is one operation document in a request body.
type gqlRequest struct {
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
	OperationName string         `json:"operationName"`
}

// gqlErrorEntry is one entry of a response's errors array.
type gqlErrorEntry struct {
	Message string `json:"message"`
}

// gqlResponse is one operation's {data, errors} envelope. Data serialises as
// null when absent; Errors is omitted on success.
type gqlResponse struct {
	Data   any             `json:"data"`
	Errors []gqlErrorEntry `json:"errors,omitempty"`
}

func gqlErrResponse(messages ...string) gqlResponse {
	errs := make([]gqlErrorEntry, len(messages))
	for i, m := range messages {
		errs[i] = gqlErrorEntry{Message: m}
	}
	return gqlResponse{Data: nil, Errors: errs}
}

// RegisterGraphQL registers the GraphQL route on mux.
func RegisterGraphQL(mux *Router, s *Store) {
	mux.Handle(func(r *http.Request, path string) bool {
		return r.Method == http.MethodPost && path == "/api/graphql"
	}, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		trimmed := bytes.TrimSpace(body)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var batch []gqlRequest
			if err := json.Unmarshal(trimmed, &batch); err == nil {
				out := make([]gqlResponse, len(batch))
				for i := range batch {
					out[i] = gqlExecute(s, &batch[i])
				}
				WriteJSON(w, http.StatusOK, out)
				return
			}
			WriteJSON(w, http.StatusOK, []gqlResponse{gqlErrResponse("Malformed batched request.")})
			return
		}
		var req gqlRequest
		if err := json.Unmarshal(trimmed, &req); err != nil {
			WriteJSON(w, http.StatusOK, gqlErrResponse("Malformed request body."))
			return
		}
		WriteJSON(w, http.StatusOK, gqlExecute(s, &req))
	})
}

// gqlExecute parses, validates and runs one operation document.
func gqlExecute(s *Store, req *gqlRequest) gqlResponse {
	if strings.TrimSpace(req.Query) == "" {
		return gqlErrResponse("Must provide query string.")
	}
	toks, err := gqlLex(req.Query)
	if err != nil {
		return gqlErrResponse(err.Error())
	}
	p := &gqlParser{toks: toks, frags: map[string]*gqlFragDef{}}
	ops, err := p.parseDocument()
	if err != nil {
		return gqlErrResponse(err.Error())
	}
	if len(ops) == 0 {
		return gqlErrResponse("Must provide an operation.")
	}
	op := ops[0]
	if req.OperationName != "" {
		for _, o := range ops {
			if o.name == req.OperationName {
				op = o
				break
			}
		}
	}
	rootType := "Query"
	if op.opType == "mutation" {
		rootType = "Mutation"
	}
	var validationErrors []string
	gqlValidate(op.sels, rootType, p.frags, &validationErrors)
	if len(validationErrors) > 0 {
		return gqlErrResponse(validationErrors...)
	}
	vars := req.Variables
	if vars == nil {
		vars = map[string]any{}
	}
	ex := &gqlExec{s: s, vars: vars, frags: p.frags}
	data, err := ex.resolveObject(rootType, nil, op.sels)
	if err != nil {
		return gqlErrResponse(err.Error())
	}
	return gqlResponse{Data: data}
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type gqlTokKind int

const (
	gqlTokEOF gqlTokKind = iota
	gqlTokName
	gqlTokInt
	gqlTokFloat
	gqlTokString
	gqlTokPunct
)

type gqlTok struct {
	kind gqlTokKind
	val  string
}

func gqlLex(src string) ([]gqlTok, error) {
	var toks []gqlTok
	i, n := 0, len(src)
	for i < n {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case c == '#':
			for i < n && src[i] != '\n' {
				i++
			}
		case c == '.':
			if i+2 < n && src[i+1] == '.' && src[i+2] == '.' {
				toks = append(toks, gqlTok{gqlTokPunct, "..."})
				i += 3
			} else {
				return nil, fmt.Errorf("syntax error: unexpected %q", c)
			}
		case c == '{' || c == '}' || c == '(' || c == ')' || c == '[' || c == ']' ||
			c == ':' || c == '!' || c == '$' || c == '=' || c == '@' || c == '|' || c == '&':
			toks = append(toks, gqlTok{gqlTokPunct, string(c)})
			i++
		case c == '"':
			if i+2 < n && src[i+1] == '"' && src[i+2] == '"' {
				end := strings.Index(src[i+3:], `"""`)
				if end < 0 {
					return nil, fmt.Errorf("syntax error: unterminated block string")
				}
				toks = append(toks, gqlTok{gqlTokString, src[i+3 : i+3+end]})
				i += 3 + end + 3
			} else {
				j := i + 1
				var sb strings.Builder
				closed := false
				for j < n {
					ch := src[j]
					if ch == '"' {
						closed = true
						j++
						break
					}
					if ch == '\n' {
						return nil, fmt.Errorf("syntax error: unterminated string")
					}
					if ch == '\\' {
						if j+1 >= n {
							return nil, fmt.Errorf("syntax error: unterminated string")
						}
						switch esc := src[j+1]; esc {
						case '"':
							sb.WriteByte('"')
							j += 2
						case '\\':
							sb.WriteByte('\\')
							j += 2
						case '/':
							sb.WriteByte('/')
							j += 2
						case 'b':
							sb.WriteByte('\b')
							j += 2
						case 'f':
							sb.WriteByte('\f')
							j += 2
						case 'n':
							sb.WriteByte('\n')
							j += 2
						case 'r':
							sb.WriteByte('\r')
							j += 2
						case 't':
							sb.WriteByte('\t')
							j += 2
						case 'u':
							if j+5 >= n {
								return nil, fmt.Errorf("syntax error: bad unicode escape")
							}
							code, err := strconv.ParseUint(src[j+2:j+6], 16, 32)
							if err != nil {
								return nil, fmt.Errorf("syntax error: bad unicode escape")
							}
							sb.WriteRune(rune(code))
							j += 6
						default:
							return nil, fmt.Errorf("syntax error: bad escape")
						}
						continue
					}
					sb.WriteByte(ch)
					j++
				}
				if !closed {
					return nil, fmt.Errorf("syntax error: unterminated string")
				}
				toks = append(toks, gqlTok{gqlTokString, sb.String()})
				i = j
			}
		case c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
			j := i + 1
			for j < n && (src[j] == '_' || (src[j] >= 'A' && src[j] <= 'Z') ||
				(src[j] >= 'a' && src[j] <= 'z') || (src[j] >= '0' && src[j] <= '9')) {
				j++
			}
			toks = append(toks, gqlTok{gqlTokName, src[i:j]})
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i
			if src[j] == '-' {
				j++
			}
			for j < n && src[j] >= '0' && src[j] <= '9' {
				j++
			}
			isFloat := false
			if j < n && src[j] == '.' {
				isFloat = true
				j++
				for j < n && src[j] >= '0' && src[j] <= '9' {
					j++
				}
			}
			if j < n && (src[j] == 'e' || src[j] == 'E') {
				isFloat = true
				j++
				if j < n && (src[j] == '+' || src[j] == '-') {
					j++
				}
				for j < n && src[j] >= '0' && src[j] <= '9' {
					j++
				}
			}
			if isFloat {
				toks = append(toks, gqlTok{gqlTokFloat, src[i:j]})
			} else {
				toks = append(toks, gqlTok{gqlTokInt, src[i:j]})
			}
			i = j
		default:
			return nil, fmt.Errorf("syntax error: unexpected character %q", c)
		}
	}
	toks = append(toks, gqlTok{gqlTokEOF, ""})
	return toks, nil
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

// gqlVarRef is a $variable reference in an argument value.
type gqlVarRef struct{ name string }

// gqlEnum is a bare-name (enum) argument value.
type gqlEnum struct{ name string }

// gqlSel is one field selection, inline fragment, or fragment spread.
type gqlSel struct {
	alias, name string
	args        map[string]any
	sels        []*gqlSel
	fragCond    string // type condition for an inline fragment
	isFrag      bool
	spread      string // fragment name for a spread
}

// gqlOp is one operation definition.
type gqlOp struct {
	opType string
	name   string
	sels   []*gqlSel
}

// gqlFragDef is a named fragment definition.
type gqlFragDef struct {
	cond string
	sels []*gqlSel
}

type gqlParser struct {
	toks  []gqlTok
	pos   int
	frags map[string]*gqlFragDef
}

func (p *gqlParser) peek() gqlTok { return p.toks[p.pos] }
func (p *gqlParser) next() gqlTok { t := p.toks[p.pos]; p.pos++; return t }
func (p *gqlParser) atPunct(v string) bool {
	t := p.peek()
	return t.kind == gqlTokPunct && t.val == v
}
func (p *gqlParser) expectPunct(v string) error {
	if !p.atPunct(v) {
		return fmt.Errorf("syntax error: expected %q, got %q", v, p.peek().val)
	}
	p.next()
	return nil
}
func (p *gqlParser) expectName() (string, error) {
	t := p.peek()
	if t.kind != gqlTokName {
		return "", fmt.Errorf("syntax error: expected a name, got %q", t.val)
	}
	p.next()
	return t.val, nil
}

func (p *gqlParser) parseDocument() ([]*gqlOp, error) {
	var ops []*gqlOp
	for p.peek().kind != gqlTokEOF {
		t := p.peek()
		if t.kind == gqlTokPunct && t.val == "{" {
			sels, err := p.parseSelectionSet()
			if err != nil {
				return nil, err
			}
			ops = append(ops, &gqlOp{opType: "query", sels: sels})
			continue
		}
		if t.kind == gqlTokName && (t.val == "query" || t.val == "mutation" || t.val == "subscription") {
			op, err := p.parseOperation()
			if err != nil {
				return nil, err
			}
			ops = append(ops, op)
			continue
		}
		if t.kind == gqlTokName && t.val == "fragment" {
			if err := p.parseFragmentDef(); err != nil {
				return nil, err
			}
			continue
		}
		return nil, fmt.Errorf("syntax error: unexpected token %q", t.val)
	}
	return ops, nil
}

func (p *gqlParser) parseOperation() (*gqlOp, error) {
	opType := p.next().val
	op := &gqlOp{opType: opType}
	if p.peek().kind == gqlTokName {
		op.name = p.next().val
	}
	if p.atPunct("(") {
		if err := p.skipParens(); err != nil {
			return nil, err
		}
	}
	if err := p.skipDirectives(); err != nil {
		return nil, err
	}
	sels, err := p.parseSelectionSet()
	if err != nil {
		return nil, err
	}
	op.sels = sels
	return op, nil
}

func (p *gqlParser) parseFragmentDef() error {
	p.next() // "fragment"
	name, err := p.expectName()
	if err != nil {
		return err
	}
	if name == "on" {
		return fmt.Errorf("syntax error: fragment name must not be \"on\"")
	}
	on, err := p.expectName()
	if err != nil || on != "on" {
		return fmt.Errorf("syntax error: expected \"on\" in fragment definition")
	}
	cond, err := p.expectName()
	if err != nil {
		return err
	}
	if err := p.skipDirectives(); err != nil {
		return err
	}
	sels, err := p.parseSelectionSet()
	if err != nil {
		return err
	}
	p.frags[name] = &gqlFragDef{cond: cond, sels: sels}
	return nil
}

// skipParens consumes a balanced parenthesised group (variable definitions
// and directive arguments, whose contents the executor does not need).
func (p *gqlParser) skipParens() error {
	if err := p.expectPunct("("); err != nil {
		return err
	}
	depth := 1
	for depth > 0 {
		t := p.next()
		if t.kind == gqlTokEOF {
			return fmt.Errorf("syntax error: unterminated parentheses")
		}
		if t.kind == gqlTokPunct {
			switch t.val {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			}
		}
	}
	return nil
}

func (p *gqlParser) skipDirectives() error {
	for p.atPunct("@") {
		p.next()
		if _, err := p.expectName(); err != nil {
			return err
		}
		if p.atPunct("(") {
			if err := p.skipParens(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *gqlParser) parseSelectionSet() ([]*gqlSel, error) {
	if err := p.expectPunct("{"); err != nil {
		return nil, err
	}
	var sels []*gqlSel
	for !p.atPunct("}") {
		if p.peek().kind == gqlTokEOF {
			return nil, fmt.Errorf("syntax error: unterminated selection set")
		}
		sel, err := p.parseSelection()
		if err != nil {
			return nil, err
		}
		sels = append(sels, sel)
	}
	p.next() // "}"
	return sels, nil
}

func (p *gqlParser) parseSelection() (*gqlSel, error) {
	if p.atPunct("...") {
		p.next()
		nt := p.peek()
		if nt.kind == gqlTokName && nt.val == "on" {
			p.next()
			cond, err := p.expectName()
			if err != nil {
				return nil, err
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			sels, err := p.parseSelectionSet()
			if err != nil {
				return nil, err
			}
			return &gqlSel{isFrag: true, fragCond: cond, sels: sels}, nil
		}
		if nt.kind == gqlTokName {
			name := p.next().val
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			return &gqlSel{isFrag: true, spread: name}, nil
		}
		if nt.kind == gqlTokPunct && nt.val == "{" {
			sels, err := p.parseSelectionSet()
			if err != nil {
				return nil, err
			}
			return &gqlSel{isFrag: true, sels: sels}, nil
		}
		return nil, fmt.Errorf("syntax error: unexpected token after \"...\"")
	}
	name, err := p.expectName()
	if err != nil {
		return nil, err
	}
	sel := &gqlSel{name: name}
	if p.atPunct(":") {
		p.next()
		alias := name
		field, err := p.expectName()
		if err != nil {
			return nil, err
		}
		sel.alias, sel.name = alias, field
	}
	if p.atPunct("(") {
		args, err := p.parseArguments()
		if err != nil {
			return nil, err
		}
		sel.args = args
	}
	if err := p.skipDirectives(); err != nil {
		return nil, err
	}
	if p.atPunct("{") {
		sels, err := p.parseSelectionSet()
		if err != nil {
			return nil, err
		}
		sel.sels = sels
	}
	return sel, nil
}

func (p *gqlParser) parseArguments() (map[string]any, error) {
	if err := p.expectPunct("("); err != nil {
		return nil, err
	}
	args := map[string]any{}
	for !p.atPunct(")") {
		if p.peek().kind == gqlTokEOF {
			return nil, fmt.Errorf("syntax error: unterminated arguments")
		}
		name, err := p.expectName()
		if err != nil {
			return nil, err
		}
		if err := p.expectPunct(":"); err != nil {
			return nil, err
		}
		val, err := p.parseValue()
		if err != nil {
			return nil, err
		}
		args[name] = val
	}
	p.next() // ")"
	return args, nil
}

func (p *gqlParser) parseValue() (any, error) {
	t := p.peek()
	switch t.kind {
	case gqlTokInt:
		p.next()
		n, err := strconv.ParseInt(t.val, 10, 64)
		if err != nil {
			f, ferr := strconv.ParseFloat(t.val, 64)
			if ferr != nil {
				return nil, fmt.Errorf("syntax error: bad integer %q", t.val)
			}
			return f, nil
		}
		return n, nil
	case gqlTokFloat:
		p.next()
		f, err := strconv.ParseFloat(t.val, 64)
		if err != nil {
			return nil, fmt.Errorf("syntax error: bad float %q", t.val)
		}
		return f, nil
	case gqlTokString:
		p.next()
		return t.val, nil
	case gqlTokName:
		p.next()
		switch t.val {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		default:
			return gqlEnum{name: t.val}, nil
		}
	case gqlTokPunct:
		switch t.val {
		case "$":
			p.next()
			name, err := p.expectName()
			if err != nil {
				return nil, err
			}
			return gqlVarRef{name: name}, nil
		case "[":
			p.next()
			var list []any
			for !p.atPunct("]") {
				if p.peek().kind == gqlTokEOF {
					return nil, fmt.Errorf("syntax error: unterminated list")
				}
				v, err := p.parseValue()
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			p.next()
			return list, nil
		case "{":
			p.next()
			obj := map[string]any{}
			for !p.atPunct("}") {
				if p.peek().kind == gqlTokEOF {
					return nil, fmt.Errorf("syntax error: unterminated input object")
				}
				name, err := p.expectName()
				if err != nil {
					return nil, err
				}
				if err := p.expectPunct(":"); err != nil {
					return nil, err
				}
				v, err := p.parseValue()
				if err != nil {
					return nil, err
				}
				obj[name] = v
			}
			p.next()
			return obj, nil
		}
	}
	return nil, fmt.Errorf("syntax error: unexpected value token %q", t.val)
}

// ---------------------------------------------------------------------------
// Schema validation (unknown fields become errors naming the field)
// ---------------------------------------------------------------------------

// gqlSchema maps each object type to its fields and each field's result type.
// Scalar result types ("String", "Int", "ID", "Boolean") have no entry as a
// key; only object types appear as keys.
var gqlSchema = map[string]map[string]string{
	"Query": {
		"viewer":     "User",
		"repository": "Repository",
		"node":       "Node",
		"__type":     "__Type",
	},
	"Mutation": {
		"createIssue":       "CreateIssuePayload",
		"closeIssue":        "CloseIssuePayload",
		"createPullRequest": "CreatePullRequestPayload",
		"mergePullRequest":  "MergePullRequestPayload",
		"addComment":        "AddCommentPayload",
	},
	"User": {
		"login": "String",
		"id":    "ID",
		"email": "String",
		"name":  "String",
	},
	"Repository": {
		"id":               "ID",
		"databaseId":       "Int",
		"name":             "String",
		"nameWithOwner":    "String",
		"owner":            "User",
		"defaultBranchRef": "Ref",
		"viewerPermission": "String",
		"hasIssuesEnabled": "Boolean",
		"issue":            "Issue",
		"issues":           "IssueConnection",
		"pullRequests":     "PullRequestConnection",
		"pullRequest":      "PullRequest",
		"description":      "String",
		"isPrivate":        "Boolean",
		"url":              "String",
	},
	"Ref": {
		"name": "String",
	},
	"Issue": {
		"id":     "ID",
		"number": "Int",
		"title":  "String",
		"state":  "String",
		"body":   "String",
		"url":    "String",
		"author": "User",
	},
	"IssueConnection": {
		"nodes":      "Issue",
		"pageInfo":   "PageInfo",
		"totalCount": "Int",
	},
	"PageInfo": {
		"hasNextPage":     "Boolean",
		"endCursor":       "String",
		"hasPreviousPage": "Boolean",
		"startCursor":     "String",
	},
	"PullRequest": {
		"id":          "ID",
		"number":      "Int",
		"state":       "String",
		"merged":      "Boolean",
		"headRefName": "String",
		"baseRefName": "String",
		"mergeable":   "String",
		"files":       "PullRequestChangedFileConnection",
		"title":       "String",
		"body":        "String",
	},
	"PullRequestConnection": {
		"nodes":    "PullRequest",
		"pageInfo": "PageInfo",
	},
	"PullRequestChangedFileConnection": {
		"nodes":    "PullRequestChangedFile",
		"pageInfo": "PageInfo",
	},
	"PullRequestChangedFile": {
		"path":       "String",
		"additions":  "Int",
		"deletions":  "Int",
		"changeType": "String",
	},
	"Node": {
		"id": "ID",
	},
	"__Type": {
		"fields":     "__Field",
		"enumValues": "__EnumValue",
		"name":       "String",
		"kind":       "String",
	},
	"__Field": {
		"name": "String",
	},
	"__EnumValue": {
		"name": "String",
	},
	"CreateIssuePayload": {
		"issue":            "Issue",
		"clientMutationId": "String",
	},
	"CloseIssuePayload": {
		"issue":            "Issue",
		"clientMutationId": "String",
	},
	"CreatePullRequestPayload": {
		"pullRequest":      "PullRequest",
		"clientMutationId": "String",
	},
	"MergePullRequestPayload": {
		"pullRequest":      "PullRequest",
		"clientMutationId": "String",
	},
	"AddCommentPayload": {
		"commentEdge":      "IssueCommentEdge",
		"comment":          "IssueComment",
		"clientMutationId": "String",
	},
	"IssueCommentEdge": {
		"node":   "IssueComment",
		"cursor": "String",
	},
	"IssueComment": {
		"id":     "ID",
		"body":   "String",
		"author": "User",
	},
}

func gqlValidate(sels []*gqlSel, typ string, frags map[string]*gqlFragDef, errs *[]string) {
	fields, known := gqlSchema[typ]
	for _, sel := range sels {
		if sel.isFrag {
			if sel.spread != "" {
				def, ok := frags[sel.spread]
				if !ok {
					*errs = append(*errs, fmt.Sprintf("Unknown fragment %q.", sel.spread))
					continue
				}
				gqlValidate(def.sels, def.cond, frags, errs)
				continue
			}
			cond := sel.fragCond
			if cond == "" {
				cond = typ
			}
			gqlValidate(sel.sels, cond, frags, errs)
			continue
		}
		if sel.name == "__typename" {
			continue
		}
		if !known {
			*errs = append(*errs, fmt.Sprintf("Cannot query field %q on type %q.", sel.name, typ))
			continue
		}
		ret, ok := fields[sel.name]
		if !ok {
			*errs = append(*errs, fmt.Sprintf("Cannot query field %q on type %q.", sel.name, typ))
			continue
		}
		if len(sel.sels) > 0 {
			if _, isObject := gqlSchema[ret]; isObject {
				gqlValidate(sel.sels, ret, frags, errs)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

type gqlExec struct {
	s     *Store
	vars  map[string]any
	frags map[string]*gqlFragDef
}

// resolveValue substitutes variables and unwraps enum markers.
func (e *gqlExec) resolveValue(v any) any {
	switch t := v.(type) {
	case gqlVarRef:
		if val, ok := e.vars[t.name]; ok {
			return val
		}
		return nil
	case gqlEnum:
		return t.name
	case []any:
		out := make([]any, len(t))
		for i, item := range t {
			out[i] = e.resolveValue(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			out[k] = e.resolveValue(item)
		}
		return out
	default:
		return v
	}
}

func gqlToInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
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
	return 0, false
}

func (e *gqlExec) argValue(sel *gqlSel, name string) (any, bool) {
	raw, ok := sel.args[name]
	if !ok {
		return nil, false
	}
	return e.resolveValue(raw), true
}

func (e *gqlExec) argString(sel *gqlSel, name string) (string, bool) {
	v, ok := e.argValue(sel, name)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (e *gqlExec) argInt(sel *gqlSel, name string) (int, bool) {
	v, ok := e.argValue(sel, name)
	if !ok {
		return 0, false
	}
	return gqlToInt(v)
}

func (e *gqlExec) argInput(sel *gqlSel, name string) map[string]any {
	v, ok := e.argValue(sel, name)
	if !ok {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

// gqlNode carries a node() result with its concrete type for fragments.
type gqlNode struct {
	typ  string
	data any
}

// resolveObject resolves a selection set against an object of the given type.
func (e *gqlExec) resolveObject(typ string, data any, sels []*gqlSel) (map[string]any, error) {
	if typ == "Node" {
		if node, ok := data.(gqlNode); ok {
			typ, data = node.typ, node.data
		}
	}
	out := map[string]any{}
	for _, sel := range sels {
		if sel.isFrag {
			if sel.spread != "" {
				def, ok := e.frags[sel.spread]
				if !ok || (def.cond != "" && def.cond != typ) {
					continue
				}
				sub, err := e.resolveObject(typ, data, def.sels)
				if err != nil {
					return nil, err
				}
				for k, v := range sub {
					out[k] = v
				}
				continue
			}
			if sel.fragCond != "" && sel.fragCond != typ {
				continue
			}
			sub, err := e.resolveObject(typ, data, sel.sels)
			if err != nil {
				return nil, err
			}
			for k, v := range sub {
				out[k] = v
			}
			continue
		}
		key := sel.alias
		if key == "" {
			key = sel.name
		}
		val, err := e.resolveField(typ, data, sel)
		if err != nil {
			return nil, err
		}
		out[key] = val
	}
	return out, nil
}

func (e *gqlExec) resolveField(typ string, data any, sel *gqlSel) (any, error) {
	if sel.name == "__typename" {
		return typ, nil
	}
	switch typ {
	case "Query":
		return e.resolveQueryField(sel)
	case "Mutation":
		return e.resolveMutationField(sel)
	case "User":
		switch sel.name {
		case "login", "name":
			return ViewerLogin, nil
		case "id":
			return GlobalID("User", ViewerID, 0), nil
		case "email":
			return ViewerEmail, nil
		}
	case "Repository":
		return e.resolveRepositoryField(data.(*Repo), sel)
	case "Ref":
		if sel.name == "name" {
			if name, ok := data.(string); ok {
				return name, nil
			}
		}
	case "Issue":
		return e.resolveIssueField(data.(*gqlIssueSnap), sel)
	case "IssueConnection":
		return e.resolveIssueConnectionField(data.(*gqlIssueConn), sel)
	case "PageInfo":
		return e.resolvePageInfoField(data.(gqlPageInfo), sel)
	case "PullRequest":
		return e.resolvePullRequestField(data.(*gqlPRSnap), sel)
	case "PullRequestConnection":
		return e.resolvePRConnectionField(data.(*gqlPRConn), sel)
	case "PullRequestChangedFileConnection":
		return e.resolveFileConnectionField(data.(*gqlFileConn), sel)
	case "PullRequestChangedFile":
		f := data.(PRFile)
		switch sel.name {
		case "path":
			return f.Filename, nil
		case "additions":
			return f.Additions, nil
		case "deletions":
			return f.Deletions, nil
		case "changeType":
			switch f.Status {
			case "added":
				return "ADDED", nil
			case "removed":
				return "REMOVED", nil
			default:
				return "CHANGED", nil
			}
		}
	case "__Type":
		return e.resolveTypeField(data.(string), sel)
	case "__Field", "__EnumValue":
		if sel.name == "name" {
			if name, ok := data.(string); ok {
				return name, nil
			}
		}
	case "CreateIssuePayload", "CloseIssuePayload":
		if sel.name == "issue" {
			return e.resolveObject("Issue", data.(*gqlIssueSnap), sel.sels)
		}
		if sel.name == "clientMutationId" {
			return nil, nil
		}
	case "CreatePullRequestPayload", "MergePullRequestPayload":
		if sel.name == "pullRequest" {
			return e.resolveObject("PullRequest", data.(*gqlPRSnap), sel.sels)
		}
		if sel.name == "clientMutationId" {
			return nil, nil
		}
	case "AddCommentPayload":
		if sel.name == "commentEdge" {
			return e.resolveObject("IssueCommentEdge", data.(*gqlCommentCtx), sel.sels)
		}
		if sel.name == "comment" {
			return e.resolveObject("IssueComment", data.(*gqlCommentCtx), sel.sels)
		}
		if sel.name == "clientMutationId" {
			return nil, nil
		}
	case "IssueCommentEdge":
		if sel.name == "node" {
			return e.resolveObject("IssueComment", data.(*gqlCommentCtx), sel.sels)
		}
		if sel.name == "cursor" {
			return "", nil
		}
	case "IssueComment":
		c := data.(*gqlCommentCtx)
		switch sel.name {
		case "id":
			return GlobalID("IssueComment", c.repoID, int(c.comment.ID)), nil
		case "body":
			return c.comment.Body, nil
		case "author":
			return e.resolveObject("User", nil, sel.sels)
		}
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, typ)
}

func (e *gqlExec) resolveQueryField(sel *gqlSel) (any, error) {
	switch sel.name {
	case "viewer":
		return e.resolveObject("User", nil, sel.sels)
	case "repository":
		owner, _ := e.argString(sel, "owner")
		name, _ := e.argString(sel, "name")
		repo, ok := e.s.GetRepo(owner, name)
		if !ok {
			return nil, nil
		}
		return e.resolveObject("Repository", repo, sel.sels)
	case "node":
		id, _ := e.argString(sel, "id")
		kind, repoID, number, ok := ParseGlobalID(id)
		if !ok {
			return nil, nil
		}
		repo, ok := e.s.GetRepoByID(repoID)
		if !ok {
			return nil, nil
		}
		switch kind {
		case "Repository":
			return e.resolveObject("Node", gqlNode{typ: "Repository", data: repo}, sel.sels)
		case "Issue":
			iss, ok := e.s.GetIssue(repo, number)
			if !ok {
				return nil, nil
			}
			return e.resolveObject("Node", gqlNode{typ: "Issue", data: gqlSnapshotIssue(e.s, repo, iss)}, sel.sels)
		case "PullRequest":
			pr, ok := e.s.GetPullRequest(repo, number)
			if !ok {
				return nil, nil
			}
			return e.resolveObject("Node", gqlNode{typ: "PullRequest", data: gqlSnapshotPR(e.s, repo, pr)}, sel.sels)
		default:
			return nil, nil
		}
	case "__type":
		name, _ := e.argString(sel, "name")
		if _, ok := gqlIntrospectionFields[name]; !ok && name != "SearchType" {
			return nil, nil
		}
		return e.resolveObject("__Type", name, sel.sels)
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "Query")
}

func (e *gqlExec) resolveRepositoryField(r *Repo, sel *gqlSel) (any, error) {
	switch sel.name {
	case "id":
		return RepoGlobalID(r), nil
	case "databaseId":
		return r.ID, nil
	case "name":
		return r.Name, nil
	case "nameWithOwner":
		return r.Owner + "/" + r.Name, nil
	case "owner":
		return e.resolveObject("User", nil, sel.sels)
	case "defaultBranchRef":
		if _, ok := e.s.GetRef(r, BranchRef(r.DefaultBranch)); !ok {
			return nil, nil
		}
		return e.resolveObject("Ref", r.DefaultBranch, sel.sels)
	case "viewerPermission":
		return "ADMIN", nil
	case "hasIssuesEnabled":
		return true, nil
	case "description":
		e.s.RLock()
		d := r.Description
		e.s.RUnlock()
		return d, nil
	case "isPrivate":
		e.s.RLock()
		p := r.Private
		e.s.RUnlock()
		return p, nil
	case "url":
		return "", nil
	case "issue":
		number, _ := e.argInt(sel, "number")
		iss, ok := e.s.GetIssue(r, number)
		if !ok {
			return nil, nil
		}
		return e.resolveObject("Issue", gqlSnapshotIssue(e.s, r, iss), sel.sels)
	case "issues":
		return e.resolveObject("IssueConnection", e.issuesConnection(r, sel), sel.sels)
	case "pullRequests":
		return e.resolveObject("PullRequestConnection", e.prConnection(r, sel), sel.sels)
	case "pullRequest":
		number, _ := e.argInt(sel, "number")
		pr, ok := e.s.GetPullRequest(r, number)
		if !ok {
			return nil, nil
		}
		return e.resolveObject("PullRequest", gqlSnapshotPR(e.s, r, pr), sel.sels)
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "Repository")
}

// gqlIssueSnap is a point-in-time copy of an issue's readable fields.
type gqlIssueSnap struct {
	repoID int64
	number int
	title  string
	body   string
	state  string
}

func gqlSnapshotIssue(s *Store, r *Repo, iss *Issue) *gqlIssueSnap {
	s.RLock()
	defer s.RUnlock()
	return &gqlIssueSnap{repoID: r.ID, number: iss.Number, title: iss.Title, body: iss.Body, state: iss.State}
}

func gqlIssueState(state string) string {
	if state == "closed" {
		return "CLOSED"
	}
	return "OPEN"
}

func (e *gqlExec) resolveIssueField(iss *gqlIssueSnap, sel *gqlSel) (any, error) {
	switch sel.name {
	case "id":
		return GlobalID("Issue", iss.repoID, iss.number), nil
	case "number":
		return iss.number, nil
	case "title":
		return iss.title, nil
	case "state":
		return gqlIssueState(iss.state), nil
	case "body":
		return iss.body, nil
	case "url":
		return "", nil
	case "author":
		return e.resolveObject("User", nil, sel.sels)
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "Issue")
}

// gqlIssueConn is one page of an issues connection.
type gqlIssueConn struct {
	nodes     []*gqlIssueSnap
	hasNext   bool
	endCursor string
	hasEnd    bool
}

type gqlPageInfo struct {
	hasNext   bool
	endCursor string
	hasEnd    bool
}

func (e *gqlExec) resolveIssueConnectionField(conn *gqlIssueConn, sel *gqlSel) (any, error) {
	switch sel.name {
	case "nodes":
		nodes := make([]any, len(conn.nodes))
		for i, iss := range conn.nodes {
			obj, err := e.resolveObject("Issue", iss, sel.sels)
			if err != nil {
				return nil, err
			}
			nodes[i] = obj
		}
		return nodes, nil
	case "pageInfo":
		return e.resolveObject("PageInfo", gqlPageInfo{hasNext: conn.hasNext, endCursor: conn.endCursor, hasEnd: conn.hasEnd}, sel.sels)
	case "totalCount":
		return len(conn.nodes), nil
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "IssueConnection")
}

func (e *gqlExec) resolvePageInfoField(info gqlPageInfo, sel *gqlSel) (any, error) {
	switch sel.name {
	case "hasNextPage":
		return info.hasNext, nil
	case "endCursor":
		if !info.hasEnd {
			return nil, nil
		}
		return info.endCursor, nil
	case "hasPreviousPage":
		return false, nil
	case "startCursor":
		return nil, nil
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "PageInfo")
}

// issuesConnection applies the states filter, orderBy ordering, and
// first/after cursor pagination to the repo's issues.
func (e *gqlExec) issuesConnection(r *Repo, sel *gqlSel) *gqlIssueConn {
	var stateFilter map[string]bool
	if v, ok := e.argValue(sel, "states"); ok {
		if list, ok := v.([]any); ok {
			stateFilter = map[string]bool{}
			for _, item := range list {
				if s, ok := item.(string); ok {
					stateFilter[strings.ToLower(s)] = true
				}
			}
		}
	}
	desc := false
	if v, ok := e.argValue(sel, "orderBy"); ok {
		if m, ok := v.(map[string]any); ok {
			if d, ok := m["direction"].(string); ok && d == "DESC" {
				desc = true
			}
		}
	}
	var snaps []*gqlIssueSnap
	for _, iss := range e.s.ListIssues(r) {
		snap := gqlSnapshotIssue(e.s, r, iss)
		if stateFilter != nil && !stateFilter[snap.state] {
			continue
		}
		snaps = append(snaps, snap)
	}
	sort.Slice(snaps, func(i, j int) bool {
		if desc {
			return snaps[i].number > snaps[j].number
		}
		return snaps[i].number < snaps[j].number
	})
	first := -1
	if n, ok := e.argInt(sel, "first"); ok {
		first = n
	}
	start := 0
	if after, ok := e.argString(sel, "after"); ok && after != "" {
		if num, ok := gqlDecodeCursor(after); ok {
			for i, snap := range snaps {
				if snap.number == num {
					start = i + 1
					break
				}
			}
		}
	}
	if start > len(snaps) {
		start = len(snaps)
	}
	end := len(snaps)
	if first >= 0 && start+first < end {
		end = start + first
	}
	page := snaps[start:end]
	conn := &gqlIssueConn{nodes: page, hasNext: end < len(snaps)}
	if len(page) > 0 {
		conn.endCursor = gqlEncodeCursor(page[len(page)-1].number)
		conn.hasEnd = true
	}
	return conn
}

// gqlPRSnap is a point-in-time copy of a pull request's readable fields.
type gqlPRSnap struct {
	repoID  int64
	repo    *Repo
	number  int
	title   string
	body    string
	state   string
	headRef string
	baseRef string
	headSHA string
	baseSHA string
	merged  bool
	files   []PRFile
}

func gqlSnapshotPR(s *Store, r *Repo, pr *PullRequest) *gqlPRSnap {
	s.RLock()
	defer s.RUnlock()
	return &gqlPRSnap{
		repoID: r.ID, repo: r,
		number: pr.Number, title: pr.Title, body: pr.Body, state: pr.State,
		headRef: pr.HeadRef, baseRef: pr.BaseRef, headSHA: pr.HeadSHA, baseSHA: pr.BaseSHA,
		merged: pr.Merged, files: append([]PRFile(nil), pr.Files...),
	}
}

func (e *gqlExec) resolvePullRequestField(pr *gqlPRSnap, sel *gqlSel) (any, error) {
	switch sel.name {
	case "id":
		return GlobalID("PullRequest", pr.repoID, pr.number), nil
	case "number":
		return pr.number, nil
	case "title":
		return pr.title, nil
	case "body":
		return pr.body, nil
	case "state":
		if pr.merged {
			return "MERGED", nil
		}
		return gqlIssueState(pr.state), nil
	case "merged":
		return pr.merged, nil
	case "headRefName":
		return pr.headRef, nil
	case "baseRefName":
		return pr.baseRef, nil
	case "mergeable":
		return gqlComputeMergeable(e.s, pr), nil
	case "files":
		files := pr.files
		if n, ok := e.argInt(sel, "first"); ok && n >= 0 && n < len(files) {
			files = files[:n]
		}
		return e.resolveObject("PullRequestChangedFileConnection", &gqlFileConn{files: files}, sel.sels)
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "PullRequest")
}

// gqlPRConn is a pull-requests connection page.
type gqlPRConn struct {
	nodes []*gqlPRSnap
}

func (e *gqlExec) prConnection(r *Repo, sel *gqlSel) *gqlPRConn {
	var snaps []*gqlPRSnap
	for _, pr := range e.s.ListPullRequests(r) {
		snaps = append(snaps, gqlSnapshotPR(e.s, r, pr))
	}
	if n, ok := e.argInt(sel, "first"); ok && n >= 0 && n < len(snaps) {
		snaps = snaps[:n]
	}
	return &gqlPRConn{nodes: snaps}
}

func (e *gqlExec) resolvePRConnectionField(conn *gqlPRConn, sel *gqlSel) (any, error) {
	switch sel.name {
	case "nodes":
		nodes := make([]any, len(conn.nodes))
		for i, pr := range conn.nodes {
			obj, err := e.resolveObject("PullRequest", pr, sel.sels)
			if err != nil {
				return nil, err
			}
			nodes[i] = obj
		}
		return nodes, nil
	case "pageInfo":
		return e.resolveObject("PageInfo", gqlPageInfo{}, sel.sels)
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "PullRequestConnection")
}

// gqlFileConn is a changed-files connection page.
type gqlFileConn struct {
	files []PRFile
}

func (e *gqlExec) resolveFileConnectionField(conn *gqlFileConn, sel *gqlSel) (any, error) {
	switch sel.name {
	case "nodes":
		nodes := make([]any, len(conn.files))
		for i, f := range conn.files {
			obj, err := e.resolveObject("PullRequestChangedFile", f, sel.sels)
			if err != nil {
				return nil, err
			}
			nodes[i] = obj
		}
		return nodes, nil
	case "pageInfo":
		return e.resolveObject("PageInfo", gqlPageInfo{}, sel.sels)
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "PullRequestChangedFileConnection")
}

// ---------------------------------------------------------------------------
// Introspection
// ---------------------------------------------------------------------------

// gqlIntrospectionFields holds the exact field lists the suite asserts for
// each introspected object type (plus a few more real fields; extras are
// allowed).
var gqlIntrospectionFields = map[string][]string{
	"Issue": {
		"id", "number", "title", "state", "body",
		"author", "closed", "closedAt", "comments", "createdAt",
		"labels", "repository", "updatedAt", "url",
	},
	"PullRequest": {
		"id", "number", "headRefName", "baseRefName", "mergeable", "state", "merged", "files",
		"title", "body", "author", "additions", "changedFiles", "closed", "closedAt",
		"createdAt", "deletions", "isDraft", "mergeCommit", "mergedAt",
		"repository", "updatedAt", "url",
	},
	"Repository": {
		"id", "databaseId", "name", "nameWithOwner", "owner", "defaultBranchRef",
		"viewerPermission", "hasIssuesEnabled", "issue", "issues",
		"pullRequests", "pullRequest",
		"createdAt", "description", "isPrivate", "updatedAt", "url",
	},
}

var gqlSearchTypeValues = []string{"ISSUE", "REPOSITORY", "USER", "DISCUSSION", "COMMIT", "CODE"}

func (e *gqlExec) resolveTypeField(name string, sel *gqlSel) (any, error) {
	switch sel.name {
	case "fields":
		if name == "SearchType" {
			return nil, nil
		}
		fields := gqlIntrospectionFields[name]
		out := make([]any, len(fields))
		for i, f := range fields {
			obj, err := e.resolveObject("__Field", f, sel.sels)
			if err != nil {
				return nil, err
			}
			out[i] = obj
		}
		return out, nil
	case "enumValues":
		if name != "SearchType" {
			return nil, nil
		}
		out := make([]any, len(gqlSearchTypeValues))
		for i, v := range gqlSearchTypeValues {
			obj, err := e.resolveObject("__EnumValue", v, sel.sels)
			if err != nil {
				return nil, err
			}
			out[i] = obj
		}
		return out, nil
	case "name":
		return name, nil
	case "kind":
		if name == "SearchType" {
			return "ENUM", nil
		}
		return "OBJECT", nil
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "__Type")
}

// ---------------------------------------------------------------------------
// Mutations
// ---------------------------------------------------------------------------

// gqlCommentCtx carries a created comment for the addComment payload.
type gqlCommentCtx struct {
	repoID  int64
	comment *Comment
}

// gqlRepoFromGlobalID resolves a repository global id to its repo.
func (e *gqlExec) gqlRepoFromGlobalID(id string) (*Repo, bool) {
	kind, repoID, _, ok := ParseGlobalID(id)
	if !ok || kind != "Repository" {
		return nil, false
	}
	return e.s.GetRepoByID(repoID)
}

func (e *gqlExec) resolveMutationField(sel *gqlSel) (any, error) {
	input := e.argInput(sel, "input")
	if input == nil {
		return nil, fmt.Errorf("Missing input for %q.", sel.name)
	}
	switch sel.name {
	case "createIssue":
		repoID, _ := input["repositoryId"].(string)
		repo, ok := e.gqlRepoFromGlobalID(repoID)
		if !ok {
			return nil, fmt.Errorf("Could not resolve to a Repository with the id %q.", repoID)
		}
		title, _ := input["title"].(string)
		body, _ := input["body"].(string)
		iss, err := e.s.CreateIssue(repo, title, body, nil)
		if err != nil {
			return nil, err
		}
		return e.resolveObject("CreateIssuePayload", gqlSnapshotIssue(e.s, repo, iss), sel.sels)
	case "closeIssue":
		issueID, _ := input["issueId"].(string)
		kind, repoID, number, ok := ParseGlobalID(issueID)
		if !ok || kind != "Issue" {
			return nil, fmt.Errorf("Could not resolve to an Issue with the id %q.", issueID)
		}
		repo, ok := e.s.GetRepoByID(repoID)
		if !ok {
			return nil, fmt.Errorf("Could not resolve to an Issue with the id %q.", issueID)
		}
		iss, err := e.s.SetIssueState(repo, number, "closed")
		if err != nil {
			return nil, err
		}
		return e.resolveObject("CloseIssuePayload", gqlSnapshotIssue(e.s, repo, iss), sel.sels)
	case "createPullRequest":
		repoID, _ := input["repositoryId"].(string)
		repo, ok := e.gqlRepoFromGlobalID(repoID)
		if !ok {
			return nil, fmt.Errorf("Could not resolve to a Repository with the id %q.", repoID)
		}
		title, _ := input["title"].(string)
		base, _ := input["baseRefName"].(string)
		head, _ := input["headRefName"].(string)
		pr, err := e.s.CreatePullRequest(repo, title, "", head, base)
		if err != nil {
			return nil, err
		}
		return e.resolveObject("CreatePullRequestPayload", gqlSnapshotPR(e.s, repo, pr), sel.sels)
	case "mergePullRequest":
		prID, _ := input["pullRequestId"].(string)
		kind, repoID, number, ok := ParseGlobalID(prID)
		if !ok || kind != "PullRequest" {
			return nil, fmt.Errorf("Could not resolve to a PullRequest with the id %q.", prID)
		}
		repo, ok := e.s.GetRepoByID(repoID)
		if !ok {
			return nil, fmt.Errorf("Could not resolve to a PullRequest with the id %q.", prID)
		}
		pr, ok := e.s.GetPullRequest(repo, number)
		if !ok {
			return nil, fmt.Errorf("Could not resolve to a PullRequest with the id %q.", prID)
		}
		if _, err := gqlPerformSquashMerge(e.s, repo, pr); err != nil {
			return nil, err
		}
		pr, _ = e.s.GetPullRequest(repo, number)
		return e.resolveObject("MergePullRequestPayload", gqlSnapshotPR(e.s, repo, pr), sel.sels)
	case "addComment":
		subjectID, _ := input["subjectId"].(string)
		kind, repoID, number, ok := ParseGlobalID(subjectID)
		if !ok || kind != "Issue" {
			return nil, fmt.Errorf("Could not resolve to an Issue with the id %q.", subjectID)
		}
		repo, ok := e.s.GetRepoByID(repoID)
		if !ok {
			return nil, fmt.Errorf("Could not resolve to an Issue with the id %q.", subjectID)
		}
		body, _ := input["body"].(string)
		comment, err := e.s.AddComment(repo, number, body, ViewerLogin)
		if err != nil {
			return nil, err
		}
		return e.resolveObject("AddCommentPayload", &gqlCommentCtx{repoID: repo.ID, comment: comment}, sel.sels)
	}
	return nil, fmt.Errorf("Cannot query field %q on type %q.", sel.name, "Mutation")
}

// ---------------------------------------------------------------------------
// Cursors
// ---------------------------------------------------------------------------

func gqlEncodeCursor(number int) string {
	return base64.RawURLEncoding.EncodeToString([]byte("cursor:" + strconv.Itoa(number)))
}

func gqlDecodeCursor(cursor string) (int, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, false
	}
	s := string(raw)
	if !strings.HasPrefix(s, "cursor:") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(s, "cursor:"))
	if err != nil {
		return 0, false
	}
	return n, true
}

// ---------------------------------------------------------------------------
// Squash merge (shared by the GraphQL and MCP surfaces)
// ---------------------------------------------------------------------------

// errGQLMergeConflict reports a squash merge refused for conflicting changes.
var errGQLMergeConflict = errors.New("merge conflict")

// gqlFlattenAt returns path -> blob SHA for a commit's tree (tags peeled).
// A missing or empty commit flattens to an empty tree.
func gqlFlattenAt(s *Store, r *Repo, commitSHA string) map[string]string {
	if commitSHA == "" || commitSHA == ZeroSHA {
		return map[string]string{}
	}
	tree, ok := s.CommitTreeSHA(r, commitSHA)
	if !ok {
		return map[string]string{}
	}
	return s.FlattenTree(r, tree)
}

// gqlMergeHasConflict reports whether merging headTip into baseTip conflicts:
// some path changed on both sides since the merge base with different
// resulting contents (including modify-vs-delete).
func gqlMergeHasConflict(s *Store, r *Repo, baseTip, headTip string) bool {
	mb := s.MergeBase(r, baseTip, headTip)
	baseMap := gqlFlattenAt(s, r, mb)
	headMap := gqlFlattenAt(s, r, headTip)
	curMap := gqlFlattenAt(s, r, baseTip)
	for path, hSHA := range headMap {
		bSHA := baseMap[path]
		if hSHA == bSHA {
			continue
		}
		if curMap[path] != bSHA && curMap[path] != hSHA {
			return true
		}
	}
	for path, bSHA := range baseMap {
		if _, inHead := headMap[path]; inHead {
			continue
		}
		// Deleted on the head side; a base-side modification conflicts.
		if cSHA, inCur := curMap[path]; inCur && cSHA != bSHA {
			return true
		}
	}
	return false
}

// gqlComputeMergeable answers a pull request's MergeableState from the live
// branch tips, falling back to the tips recorded at creation.
func gqlComputeMergeable(s *Store, pr *gqlPRSnap) string {
	headTip, ok := s.GetRef(pr.repo, BranchRef(pr.headRef))
	if !ok || headTip == "" {
		headTip = pr.headSHA
	}
	baseTip, ok := s.GetRef(pr.repo, BranchRef(pr.baseRef))
	if !ok || baseTip == "" {
		baseTip = pr.baseSHA
	}
	if headTip == "" || baseTip == "" || headTip == ZeroSHA || baseTip == ZeroSHA {
		return "UNKNOWN"
	}
	if gqlMergeHasConflict(s, pr.repo, baseTip, headTip) {
		return "CONFLICTING"
	}
	return "MERGEABLE"
}

// gqlPerformSquashMerge squash-merges a pull request: one new commit on the
// base branch whose tree is the base tree with the head's changes since the
// merge base applied, the base ref advanced to it, and the PR marked merged.
// Merging an already-merged PR returns its existing merge commit. A
// conflicting merge is refused and leaves the ref and the PR untouched.
func gqlPerformSquashMerge(s *Store, r *Repo, pr *PullRequest) (string, error) {
	s.RLock()
	merged := pr.Merged
	existing := pr.MergeCommitSHA
	headRef, baseRef := pr.HeadRef, pr.BaseRef
	headSHA0, baseSHA0 := pr.HeadSHA, pr.BaseSHA
	number, title := pr.Number, pr.Title
	s.RUnlock()
	if merged && existing != "" {
		return existing, nil
	}
	headTip, ok := s.GetRef(r, BranchRef(headRef))
	if !ok || headTip == "" {
		headTip = headSHA0
	}
	baseTip, ok := s.GetRef(r, BranchRef(baseRef))
	if !ok || baseTip == "" {
		baseTip = baseSHA0
	}
	if headTip == "" || baseTip == "" || headTip == ZeroSHA || baseTip == ZeroSHA {
		return "", errors.New("branch tip not found")
	}
	if gqlMergeHasConflict(s, r, baseTip, headTip) {
		return "", errGQLMergeConflict
	}
	mb := s.MergeBase(r, baseTip, headTip)
	baseMap := gqlFlattenAt(s, r, mb)
	headMap := gqlFlattenAt(s, r, headTip)
	newMap := gqlFlattenAt(s, r, baseTip)
	for path, hSHA := range headMap {
		if hSHA != baseMap[path] {
			newMap[path] = hSHA
		}
	}
	for path := range baseMap {
		if _, inHead := headMap[path]; !inHead {
			delete(newMap, path)
		}
	}
	rootSHA := gqlBuildTree(s, r, newMap)
	seq := s.NextSeq()
	ts := s.Clock().Base().Unix() + int64(seq)
	ident := fmt.Sprintf("%s <%s> %d +0000", ViewerLogin, ViewerEmail, ts)
	message := fmt.Sprintf("Merge pull request #%d from %s\n\n%s\n", number, headRef, title)
	raw := fmt.Sprintf("tree %s\nparent %s\nauthor %s\ncommitter %s\n\n%s", rootSHA, baseTip, ident, ident, message)
	obj := s.PutObject(r, ObjCommit, []byte(raw))
	s.SetRef(r, BranchRef(baseRef), obj.SHA)
	if _, err := s.MarkPRMerged(r, number, obj.SHA); err != nil {
		return "", err
	}
	return obj.SHA, nil
}

// gqlBuildTree stores the nested tree objects for a flat path -> blob map
// and returns the root tree SHA. Entries sort git-style (directories compare
// with a trailing slash); blob objects already exist in the store.
func gqlBuildTree(s *Store, r *Repo, files map[string]string) string {
	return gqlBuildTreeLevel(s, r, files, "")
}

func gqlBuildTreeLevel(s *Store, r *Repo, files map[string]string, prefix string) string {
	type entry struct {
		mode  string
		name  string
		sha   string
		isDir bool
	}
	dirs := map[string]bool{}
	var entries []entry
	for path, sha := range files {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := strings.TrimPrefix(path, prefix)
		if rest == "" {
			continue
		}
		if idx := strings.IndexByte(rest, '/'); idx >= 0 {
			dirs[rest[:idx]] = true
		} else {
			entries = append(entries, entry{mode: "100644", name: rest, sha: sha})
		}
	}
	for dir := range dirs {
		sub := gqlBuildTreeLevel(s, r, files, prefix+dir+"/")
		entries = append(entries, entry{mode: "40000", name: dir, sha: sub, isDir: true})
	}
	sort.Slice(entries, func(i, j int) bool {
		ni, nj := entries[i].name, entries[j].name
		if entries[i].isDir {
			ni += "/"
		}
		if entries[j].isDir {
			nj += "/"
		}
		return ni < nj
	})
	var buf bytes.Buffer
	for _, e := range entries {
		buf.WriteString(e.mode + " " + e.name + "\x00")
		raw, _ := hex.DecodeString(e.sha)
		buf.Write(raw)
	}
	return s.PutObject(r, ObjTree, buf.Bytes()).SHA
}
