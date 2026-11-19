package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// GraphQL v4 endpoint: POST /api/graphql.
//
// A small hand-written document parser plus a resolver that walks the store.
// No GraphQL library is used; only the shapes the conformance suite sends
// are supported (queries, mutations, aliases, inline fragments, variables,
// batched operation arrays).

func encodeNodeID(kind string, id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(kind + ":" + strconv.FormatInt(id, 10)))
}

func encodeOpaque(text string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(text))
}

func decodeNodeID(raw string) (string, int64, bool) {
	plain, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return "", 0, false
	}
	parts := strings.SplitN(string(plain), ":", 2)
	if len(parts) != 2 {
		return "", 0, false
	}
	num, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return parts[0], num, true
}

func encodeCursor(num int) string {
	return encodeOpaque("cursor:" + strconv.Itoa(num))
}

func decodeCursor(raw string) (int, bool) {
	plain, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return 0, false
	}
	text := string(plain)
	if !strings.HasPrefix(text, "cursor:") {
		return 0, false
	}
	num, err := strconv.Atoi(strings.TrimPrefix(text, "cursor:"))
	if err != nil {
		return 0, false
	}
	return num, true
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

type gqlTokKind int

const (
	tokEOF gqlTokKind = iota
	tokName
	tokInt
	tokFloat
	tokStr
	tokPunct
)

type gqlTok struct {
	kind gqlTokKind
	text string
}

func gqlLex(src string) ([]gqlTok, error) {
	var out []gqlTok
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '"':
			i++
			var sb strings.Builder
			for i < len(src) && src[i] != '"' {
				if src[i] == '\\' && i+1 < len(src) {
					i++
					switch src[i] {
					case 'n':
						sb.WriteByte('\n')
					case 't':
						sb.WriteByte('\t')
					case 'r':
						sb.WriteByte('\r')
					case 'b':
						sb.WriteByte('\b')
					case 'f':
						sb.WriteByte('\f')
					case '/':
						sb.WriteByte('/')
					case '\\':
						sb.WriteByte('\\')
					case '"':
						sb.WriteByte('"')
					case 'u':
						if i+4 < len(src) {
							code, err := strconv.ParseInt(src[i+1:i+5], 16, 32)
							if err == nil {
								sb.WriteRune(rune(code))
							}
							i += 4
						}
					default:
						sb.WriteByte(src[i])
					}
					i++
				} else {
					sb.WriteByte(src[i])
					i++
				}
			}
			if i >= len(src) {
				return nil, fmt.Errorf("unterminated string")
			}
			i++
			out = append(out, gqlTok{kind: tokStr, text: sb.String()})
		case c == '.':
			if i+2 < len(src) && src[i+1] == '.' && src[i+2] == '.' {
				out = append(out, gqlTok{kind: tokPunct, text: "..."})
				i += 3
			} else {
				return nil, fmt.Errorf("unexpected dot")
			}
		case c >= '0' && c <= '9' || c == '-' && i+1 < len(src) && src[i+1] >= '0' && src[i+1] <= '9':
			start := i
			if src[i] == '-' {
				i++
			}
			for i < len(src) && src[i] >= '0' && src[i] <= '9' {
				i++
			}
			isFloat := false
			if i < len(src) && src[i] == '.' {
				isFloat = true
				i++
				for i < len(src) && src[i] >= '0' && src[i] <= '9' {
					i++
				}
			}
			if i < len(src) && (src[i] == 'e' || src[i] == 'E') {
				isFloat = true
				i++
				if i < len(src) && (src[i] == '+' || src[i] == '-') {
					i++
				}
				for i < len(src) && src[i] >= '0' && src[i] <= '9' {
					i++
				}
			}
			if isFloat {
				out = append(out, gqlTok{kind: tokFloat, text: src[start:i]})
			} else {
				out = append(out, gqlTok{kind: tokInt, text: src[start:i]})
			}
		case c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z':
			start := i
			for i < len(src) && (src[i] == '_' || src[i] >= 'a' && src[i] <= 'z' || src[i] >= 'A' && src[i] <= 'Z' || src[i] >= '0' && src[i] <= '9') {
				i++
			}
			out = append(out, gqlTok{kind: tokName, text: src[start:i]})
		case strings.IndexByte("{}()[]:!=$@|&", c) >= 0:
			out = append(out, gqlTok{kind: tokPunct, text: string(c)})
			i++
		default:
			return nil, fmt.Errorf("unexpected character %q", c)
		}
	}
	out = append(out, gqlTok{kind: tokEOF})
	return out, nil
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

type gqlVar struct{ name string }

type gqlSel struct {
	alias    string
	name     string
	args     map[string]any
	children []*gqlSel
	frag     bool
	typeCond string
}

type gqlOp struct {
	kind string
	name string
	sels []*gqlSel
}

type gqlFrag struct {
	typeCond string
	sels     []*gqlSel
}

type gqlParser struct {
	toks  []gqlTok
	pos   int
	frags map[string]*gqlFrag
}

func (p *gqlParser) peek() gqlTok { return p.toks[p.pos] }
func (p *gqlParser) next() gqlTok { t := p.toks[p.pos]; p.pos++; return t }

func (p *gqlParser) expectPunct(text string) error {
	t := p.next()
	if t.kind != tokPunct || t.text != text {
		return fmt.Errorf("expected %q, got %q", text, t.text)
	}
	return nil
}

func (p *gqlParser) expectName() (string, error) {
	t := p.next()
	if t.kind != tokName {
		return "", fmt.Errorf("expected a name, got %q", t.text)
	}
	return t.text, nil
}

// skipBalanced consumes a bracketed group starting at the current token
// (one of ( [ { ) and everything nested inside it.
func (p *gqlParser) skipBalanced() error {
	open := p.next()
	if open.kind != tokPunct {
		return fmt.Errorf("expected an opening bracket")
	}
	closers := map[string]string{"(": ")", "[": "]", "{": "}"}
	want, ok := closers[open.text]
	if !ok {
		return fmt.Errorf("expected an opening bracket, got %q", open.text)
	}
	depth := 1
	for depth > 0 {
		t := p.next()
		if t.kind == tokEOF {
			return fmt.Errorf("unterminated bracket group")
		}
		if t.kind == tokPunct {
			if t.text == open.text {
				depth++
			} else if t.text == want {
				depth--
			}
		}
	}
	return nil
}

func (p *gqlParser) skipDirectives() error {
	for p.peek().kind == tokPunct && p.peek().text == "@" {
		p.next()
		if _, err := p.expectName(); err != nil {
			return err
		}
		if p.peek().kind == tokPunct && p.peek().text == "(" {
			if err := p.skipBalanced(); err != nil {
				return err
			}
		}
	}
	return nil
}

func gqlParseDocument(src string) ([]*gqlOp, error) {
	toks, err := gqlLex(src)
	if err != nil {
		return nil, err
	}
	p := &gqlParser{toks: toks, frags: map[string]*gqlFrag{}}
	var ops []*gqlOp
	for p.peek().kind != tokEOF {
		t := p.peek()
		if t.kind == tokName && (t.text == "query" || t.text == "mutation" || t.text == "subscription") {
			kind := p.next().text
			op := &gqlOp{kind: kind}
			if p.peek().kind == tokName {
				op.name, _ = p.expectName()
			}
			if p.peek().kind == tokPunct && p.peek().text == "(" {
				if err := p.skipBalanced(); err != nil {
					return nil, err
				}
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			sels, err := p.parseSelSet()
			if err != nil {
				return nil, err
			}
			op.sels = sels
			ops = append(ops, op)
			continue
		}
		if t.kind == tokName && t.text == "fragment" {
			p.next()
			name, err := p.expectName()
			if err != nil {
				return nil, err
			}
			on, err := p.expectName()
			if err != nil || on != "on" {
				return nil, fmt.Errorf("expected on in fragment definition")
			}
			cond, err := p.expectName()
			if err != nil {
				return nil, err
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			sels, err := p.parseSelSet()
			if err != nil {
				return nil, err
			}
			p.frags[name] = &gqlFrag{typeCond: cond, sels: sels}
			continue
		}
		if t.kind == tokPunct && t.text == "{" {
			sels, err := p.parseSelSet()
			if err != nil {
				return nil, err
			}
			ops = append(ops, &gqlOp{kind: "query", sels: sels})
			continue
		}
		return nil, fmt.Errorf("unexpected token %q in document", t.text)
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	return ops, nil
}

func (p *gqlParser) parseSelSet() ([]*gqlSel, error) {
	if err := p.expectPunct("{"); err != nil {
		return nil, err
	}
	var sels []*gqlSel
	for {
		t := p.peek()
		if t.kind == tokPunct && t.text == "}" {
			p.next()
			return sels, nil
		}
		if t.kind == tokEOF {
			return nil, fmt.Errorf("unterminated selection set")
		}
		sel, err := p.parseSel()
		if err != nil {
			return nil, err
		}
		sels = append(sels, sel)
	}
}

func (p *gqlParser) parseSel() (*gqlSel, error) {
	if p.peek().kind == tokPunct && p.peek().text == "..." {
		p.next()
		if p.peek().kind == tokName && p.peek().text == "on" {
			p.next()
			cond, err := p.expectName()
			if err != nil {
				return nil, err
			}
			if err := p.skipDirectives(); err != nil {
				return nil, err
			}
			children, err := p.parseSelSet()
			if err != nil {
				return nil, err
			}
			return &gqlSel{frag: true, typeCond: cond, children: children}, nil
		}
		name, err := p.expectName()
		if err != nil {
			return nil, err
		}
		frag, ok := p.frags[name]
		if !ok {
			return nil, fmt.Errorf("unknown fragment %q", name)
		}
		if err := p.skipDirectives(); err != nil {
			return nil, err
		}
		return &gqlSel{frag: true, typeCond: frag.typeCond, children: frag.sels}, nil
	}
	first, err := p.expectName()
	if err != nil {
		return nil, err
	}
	sel := &gqlSel{}
	if p.peek().kind == tokPunct && p.peek().text == ":" {
		p.next()
		sel.alias = first
		sel.name, err = p.expectName()
		if err != nil {
			return nil, err
		}
	} else {
		sel.name = first
	}
	if p.peek().kind == tokPunct && p.peek().text == "(" {
		args, err := p.parseArgs()
		if err != nil {
			return nil, err
		}
		sel.args = args
	}
	if err := p.skipDirectives(); err != nil {
		return nil, err
	}
	if p.peek().kind == tokPunct && p.peek().text == "{" {
		children, err := p.parseSelSet()
		if err != nil {
			return nil, err
		}
		sel.children = children
	}
	return sel, nil
}

func (p *gqlParser) parseArgs() (map[string]any, error) {
	if err := p.expectPunct("("); err != nil {
		return nil, err
	}
	args := map[string]any{}
	for {
		t := p.peek()
		if t.kind == tokPunct && t.text == ")" {
			p.next()
			return args, nil
		}
		if t.kind == tokEOF {
			return nil, fmt.Errorf("unterminated argument list")
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
}

func (p *gqlParser) parseValue() (any, error) {
	t := p.next()
	switch t.kind {
	case tokPunct:
		switch t.text {
		case "$":
			name, err := p.expectName()
			if err != nil {
				return nil, err
			}
			return gqlVar{name: name}, nil
		case "[":
			var list []any
			for {
				if p.peek().kind == tokPunct && p.peek().text == "]" {
					p.next()
					return list, nil
				}
				if p.peek().kind == tokEOF {
					return nil, fmt.Errorf("unterminated list")
				}
				val, err := p.parseValue()
				if err != nil {
					return nil, err
				}
				list = append(list, val)
			}
		case "{":
			obj := map[string]any{}
			for {
				if p.peek().kind == tokPunct && p.peek().text == "}" {
					p.next()
					return obj, nil
				}
				if p.peek().kind == tokEOF {
					return nil, fmt.Errorf("unterminated input object")
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
				obj[name] = val
			}
		}
		return nil, fmt.Errorf("unexpected punctuation %q in value", t.text)
	case tokStr:
		return t.text, nil
	case tokInt:
		num, err := strconv.ParseInt(t.text, 10, 64)
		if err != nil {
			return nil, err
		}
		return num, nil
	case tokFloat:
		num, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, err
		}
		return num, nil
	case tokName:
		switch t.text {
		case "true":
			return true, nil
		case "false":
			return false, nil
		case "null":
			return nil, nil
		default:
			return t.text, nil
		}
	}
	return nil, fmt.Errorf("unexpected token %q in value", t.text)
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

type gqlCtx struct {
	a    *App
	errs []map[string]any
}

func (c *gqlCtx) addErr(msg string) {
	c.errs = append(c.errs, map[string]any{"message": msg})
}

func (c *gqlCtx) unknownField(field, typeName string) {
	c.addErr(fmt.Sprintf("Cannot query field %q on type %q.", field, typeName))
}

// nodeVal is one resolved object in the answer tree.
type nodeVal struct {
	kind        string
	repo        *Repo
	issue       *Issue
	pull        *Pull
	nodes       []*nodeVal
	hasNext     bool
	endCursor   string
	typeName    string
	commentID   string
	commentBody string
	text        string
}

func resolveVars(v any, vars map[string]any) any {
	switch t := v.(type) {
	case gqlVar:
		if vars == nil {
			return nil
		}
		return vars[t.name]
	case map[string]any:
		out := map[string]any{}
		for k, val := range t {
			out[k] = resolveVars(val, vars)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = resolveVars(val, vars)
		}
		return out
	default:
		return v
	}
}

func selKey(sel *gqlSel) string {
	if sel.alias != "" {
		return sel.alias
	}
	return sel.name
}

func argMap(sel *gqlSel, vars map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range sel.args {
		out[k] = resolveVars(v, vars)
	}
	return out
}

func argStr(args map[string]any, name string) string {
	if s, ok := args[name].(string); ok {
		return s
	}
	return ""
}

func argInt(args map[string]any, name string, def int64) int64 {
	switch v := args[name].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return def
}

func argStrList(args map[string]any, name string) []string {
	list, ok := args[name].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

var gqlTypeFields = map[string][]string{
	"Issue":       {"id", "number", "title", "state", "body", "createdAt", "updatedAt", "closedAt", "author", "labels", "comments"},
	"PullRequest": {"id", "number", "title", "body", "state", "merged", "mergeable", "headRefName", "baseRefName", "files", "createdAt", "updatedAt", "author"},
	"Repository":  {"id", "databaseId", "name", "nameWithOwner", "owner", "defaultBranchRef", "viewerPermission", "hasIssuesEnabled", "issue", "issues", "pullRequests", "pullRequest", "description", "private", "createdAt", "updatedAt"},
	"User":        {"id", "login"},
}

var gqlTypeEnums = map[string][]string{
	"SearchType":             {"COMMIT", "DISCUSSION", "ISSUE", "MILESTONE", "PACKAGE", "REPOSITORY", "USER", "WIKI"},
	"IssueState":             {"OPEN", "CLOSED"},
	"PullRequestState":       {"OPEN", "CLOSED", "MERGED"},
	"MergeableState":         {"MERGEABLE", "CONFLICTING", "UNKNOWN"},
	"OrderDirection":         {"ASC", "DESC"},
	"IssueOrderField":        {"CREATED_AT", "UPDATED_AT", "COMMENTS"},
	"RepositoryPermission":   {"ADMIN", "MAINTAIN", "WRITE", "TRIAGE", "READ"},
	"PullRequestMergeMethod": {"MERGE", "SQUASH", "REBASE"},
}

func (c *gqlCtx) resolveNode(v *nodeVal, sels []*gqlSel, vars map[string]any) map[string]any {
	out := map[string]any{}
	for _, sel := range sels {
		if sel.frag {
			if sel.typeCond == "" || sel.typeCond == v.kind {
				for k, val := range c.resolveNode(v, sel.children, vars) {
					out[k] = val
				}
			}
			continue
		}
		raw, ok := c.fieldValue(v, sel, vars)
		if !ok {
			c.unknownField(sel.name, v.kind)
			continue
		}
		out[selKey(sel)] = c.materialize(raw, sel, vars)
	}
	return out
}

func (c *gqlCtx) materialize(raw any, sel *gqlSel, vars map[string]any) any {
	switch t := raw.(type) {
	case *nodeVal:
		return c.resolveNode(t, sel.children, vars)
	case []*nodeVal:
		arr := make([]any, 0, len(t))
		for _, item := range t {
			arr = append(arr, c.resolveNode(item, sel.children, vars))
		}
		return arr
	default:
		return raw
	}
}

func (c *gqlCtx) viewerUser() *nodeVal {
	return &nodeVal{kind: "User"}
}

func (c *gqlCtx) repoNode(r *Repo) *nodeVal {
	return &nodeVal{kind: "Repository", repo: r}
}

func (c *gqlCtx) issueNode(iss *Issue) *nodeVal {
	return &nodeVal{kind: "Issue", issue: iss}
}

func (c *gqlCtx) pullNode(pr *Pull) *nodeVal {
	return &nodeVal{kind: "PullRequest", pull: pr}
}

func issueStateName(state string) string {
	if state == "closed" {
		return "CLOSED"
	}
	return "OPEN"
}

func pullStateName(pr *Pull) string {
	if pr.Merged {
		return "MERGED"
	}
	if pr.State == "closed" {
		return "CLOSED"
	}
	return "OPEN"
}

// fieldValue answers one field of one node. The second return is false
// when the field does not exist on the type.
func (c *gqlCtx) fieldValue(v *nodeVal, sel *gqlSel, vars map[string]any) (any, bool) {
	args := argMap(sel, vars)
	switch v.kind {
	case "User":
		switch sel.name {
		case "login":
			return c.a.store.ViewerLogin(), true
		case "id":
			return int64(1000), true
		}
	case "Repository":
		r := v.repo
		switch sel.name {
		case "id":
			return encodeNodeID("Repository", r.ID), true
		case "databaseId":
			return r.ID, true
		case "name":
			return r.Name, true
		case "nameWithOwner":
			return r.Owner + "/" + r.Name, true
		case "owner":
			return c.viewerUser(), true
		case "description":
			return r.Description, true
		case "private":
			return r.Private, true
		case "createdAt":
			return r.CreatedAt, true
		case "updatedAt":
			return r.UpdatedAt, true
		case "defaultBranchRef":
			if _, ok := c.a.store.BranchTip(r, r.DefaultBranch); !ok {
				return nil, true
			}
			return &nodeVal{kind: "Ref", text: r.DefaultBranch}, true
		case "viewerPermission":
			return "ADMIN", true
		case "hasIssuesEnabled":
			return true, true
		case "issue":
			num := int(argInt(args, "number", 0))
			iss := c.a.store.GetIssue(r, num)
			if iss == nil {
				return nil, true
			}
			return c.issueNode(iss), true
		case "issues":
			return c.issueConnection(r, args), true
		case "pullRequest":
			num := int(argInt(args, "number", 0))
			pr := c.a.store.GetPull(r, num)
			if pr == nil {
				return nil, true
			}
			return c.pullNode(pr), true
		case "pullRequests":
			return c.pullConnection(r, args), true
		}
	case "Issue":
		iss := v.issue
		switch sel.name {
		case "id":
			return encodeNodeID("Issue", iss.ID), true
		case "number":
			return int64(iss.Number), true
		case "title":
			return iss.Title, true
		case "state":
			return issueStateName(iss.State), true
		case "body":
			return iss.Body, true
		case "createdAt":
			return iss.CreatedAt, true
		case "updatedAt":
			return iss.UpdatedAt, true
		case "closedAt":
			if iss.State == "closed" {
				return iss.UpdatedAt, true
			}
			return nil, true
		case "author":
			return c.viewerUser(), true
		case "labels":
			return []any{}, true
		case "comments":
			return int64(iss.Comments), true
		}
	case "PullRequest":
		pr := v.pull
		switch sel.name {
		case "id":
			return encodeNodeID("PullRequest", pr.ID), true
		case "number":
			return int64(pr.Number), true
		case "title":
			return pr.Title, true
		case "body":
			return pr.Body, true
		case "state":
			return pullStateName(pr), true
		case "merged":
			return pr.Merged, true
		case "headRefName":
			return pr.Head, true
		case "baseRefName":
			return pr.Base, true
		case "mergeable":
			return c.mergeableName(pr), true
		case "files":
			return c.changedFiles(pr, args), true
		case "createdAt":
			return pr.CreatedAt, true
		case "updatedAt":
			return pr.UpdatedAt, true
		case "author":
			return c.viewerUser(), true
		}
	case "IssueConnection":
		switch sel.name {
		case "nodes":
			return v.nodes, true
		case "pageInfo":
			return &nodeVal{kind: "PageInfo", hasNext: v.hasNext, endCursor: v.endCursor}, true
		}
	case "PullRequestConnection":
		switch sel.name {
		case "nodes":
			return v.nodes, true
		case "pageInfo":
			return &nodeVal{kind: "PageInfo", hasNext: v.hasNext, endCursor: v.endCursor}, true
		}
	case "ChangedFileConnection":
		switch sel.name {
		case "nodes":
			return v.nodes, true
		case "pageInfo":
			return &nodeVal{kind: "PageInfo", hasNext: v.hasNext, endCursor: v.endCursor}, true
		}
	case "ChangedFile":
		if sel.name == "path" {
			return v.text, true
		}
	case "Ref":
		if sel.name == "name" {
			return v.text, true
		}
	case "PageInfo":
		switch sel.name {
		case "hasNextPage":
			return v.hasNext, true
		case "endCursor":
			return v.endCursor, true
		}
	case "Type":
		switch sel.name {
		case "name":
			return v.typeName, true
		case "kind":
			if _, ok := gqlTypeEnums[v.typeName]; ok {
				return "ENUM", true
			}
			return "OBJECT", true
		case "fields":
			names := gqlTypeFields[v.typeName]
			out := make([]*nodeVal, 0, len(names))
			for _, n := range names {
				out = append(out, &nodeVal{kind: "TypeField", text: n})
			}
			return out, true
		case "enumValues":
			names := gqlTypeEnums[v.typeName]
			out := make([]*nodeVal, 0, len(names))
			for _, n := range names {
				out = append(out, &nodeVal{kind: "EnumValue", text: n})
			}
			return out, true
		}
	case "TypeField", "EnumValue":
		if sel.name == "name" {
			return v.text, true
		}
	case "CreateIssuePayload", "CloseIssuePayload":
		if sel.name == "issue" {
			if v.issue == nil {
				return nil, true
			}
			return c.issueNode(v.issue), true
		}
	case "CreatePullRequestPayload", "MergePullRequestPayload":
		if sel.name == "pullRequest" {
			if v.pull == nil {
				return nil, true
			}
			return c.pullNode(v.pull), true
		}
	case "AddCommentPayload":
		if sel.name == "commentEdge" {
			return &nodeVal{kind: "CommentEdge", commentID: v.commentID, commentBody: v.commentBody}, true
		}
	case "CommentEdge":
		if sel.name == "node" {
			return &nodeVal{kind: "Comment", commentID: v.commentID, commentBody: v.commentBody}, true
		}
	case "Comment":
		switch sel.name {
		case "id":
			return v.commentID, true
		case "body":
			return v.commentBody, true
		}
	}
	return nil, false
}

func (c *gqlCtx) mergeableName(pr *Pull) string {
	if pr.State != "open" || pr.Merged {
		return "UNKNOWN"
	}
	r := c.findPullRepo(pr)
	if r == nil {
		return "UNKNOWN"
	}
	baseTip, okBase := c.a.store.BranchTip(r, pr.Base)
	headTip, okHead := c.a.store.BranchTip(r, pr.Head)
	if !okBase || !okHead {
		return "UNKNOWN"
	}
	if c.a.store.IsAncestor(r, baseTip, headTip) {
		return "MERGEABLE"
	}
	return "CONFLICTING"
}

func (c *gqlCtx) findPullRepo(pr *Pull) *Repo {
	for _, r := range c.a.store.ListRepos(c.a.store.ViewerLogin()) {
		c.a.store.mu.RLock()
		for _, cand := range r.Pulls {
			if cand == pr {
				c.a.store.mu.RUnlock()
				return r
			}
		}
		c.a.store.mu.RUnlock()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Connections, tree diff, lookups
// ---------------------------------------------------------------------------

func (c *gqlCtx) issueConnection(r *Repo, args map[string]any) *nodeVal {
	stateFilter := ""
	if states := argStrList(args, "states"); len(states) > 0 {
		wantOpen, wantClosed := false, false
		for _, s := range states {
			if s == "OPEN" {
				wantOpen = true
			}
			if s == "CLOSED" {
				wantClosed = true
			}
		}
		switch {
		case wantOpen && !wantClosed:
			stateFilter = "open"
		case wantClosed && !wantOpen:
			stateFilter = "closed"
		}
	}
	list := c.a.store.ListIssues(r, stateFilter)
	desc := false
	if order, ok := args["orderBy"].(map[string]any); ok {
		if dir, ok := order["direction"].(string); ok && dir == "DESC" {
			desc = true
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if desc {
			if list[i].Seq != list[j].Seq {
				return list[i].Seq > list[j].Seq
			}
			return list[i].Number > list[j].Number
		}
		if list[i].Seq != list[j].Seq {
			return list[i].Seq < list[j].Seq
		}
		return list[i].Number < list[j].Number
	})
	if after, ok := args["after"].(string); ok && after != "" {
		if cursorNum, ok := decodeCursor(after); ok {
			kept := list[:0]
			for _, iss := range list {
				if desc && iss.Number < cursorNum || !desc && iss.Number > cursorNum {
					kept = append(kept, iss)
				}
			}
			list = kept
		}
	}
	first := int(argInt(args, "first", 0))
	hasNext := false
	if first > 0 && len(list) > first {
		hasNext = true
		list = list[:first]
	}
	endCursor := ""
	if len(list) > 0 {
		endCursor = encodeCursor(list[len(list)-1].Number)
	}
	nodes := make([]*nodeVal, 0, len(list))
	for _, iss := range list {
		nodes = append(nodes, c.issueNode(iss))
	}
	return &nodeVal{kind: "IssueConnection", nodes: nodes, hasNext: hasNext, endCursor: endCursor}
}

func (c *gqlCtx) pullConnection(r *Repo, args map[string]any) *nodeVal {
	c.a.store.mu.RLock()
	pulls := make([]*Pull, len(r.Pulls))
	copy(pulls, r.Pulls)
	c.a.store.mu.RUnlock()
	sort.Slice(pulls, func(i, j int) bool { return pulls[i].Number < pulls[j].Number })
	first := int(argInt(args, "first", 0))
	hasNext := false
	if first > 0 && len(pulls) > first {
		hasNext = true
		pulls = pulls[:first]
	}
	nodes := make([]*nodeVal, 0, len(pulls))
	for _, pr := range pulls {
		nodes = append(nodes, c.pullNode(pr))
	}
	return &nodeVal{kind: "PullRequestConnection", nodes: nodes, hasNext: hasNext}
}

// flattenTree collects path -> blob OID for every file under a tree OID.
func (c *gqlCtx) flattenTree(r *Repo, treeOID, prefix string, out map[string]string) {
	obj := c.a.store.GetObject(r, treeOID)
	if obj == nil || obj.Tree == nil {
		return
	}
	for _, entry := range obj.Tree.Entries {
		path := prefix + entry.Name
		child := c.a.store.GetObject(r, entry.OID)
		if child != nil && child.Type == "tree" {
			c.flattenTree(r, entry.OID, path+"/", out)
		} else {
			out[path] = entry.OID
		}
	}
}

func (c *gqlCtx) commitTreeOID(r *Repo, commitSHA string) (string, bool) {
	obj := c.a.store.GetObject(r, commitSHA)
	if obj == nil || obj.Commit == nil {
		return "", false
	}
	return obj.Commit.Tree, true
}

func (c *gqlCtx) changedFiles(pr *Pull, args map[string]any) *nodeVal {
	r := c.findPullRepo(pr)
	var paths []string
	if r != nil {
		baseTip, okBase := c.a.store.BranchTip(r, pr.Base)
		headTip, okHead := c.a.store.BranchTip(r, pr.Head)
		if okBase && okHead {
			baseTree, okB := c.commitTreeOID(r, baseTip)
			headTree, okH := c.commitTreeOID(r, headTip)
			if okB && okH {
				baseFiles := map[string]string{}
				headFiles := map[string]string{}
				c.flattenTree(r, baseTree, "", baseFiles)
				c.flattenTree(r, headTree, "", headFiles)
				seen := map[string]bool{}
				for path, oid := range headFiles {
					if baseFiles[path] != oid {
						paths = append(paths, path)
						seen[path] = true
					}
				}
				for path := range baseFiles {
					if _, ok := headFiles[path]; !ok && !seen[path] {
						paths = append(paths, path)
					}
				}
				sort.Strings(paths)
			}
		}
	}
	first := int(argInt(args, "first", 0))
	hasNext := false
	if first > 0 && len(paths) > first {
		hasNext = true
		paths = paths[:first]
	}
	nodes := make([]*nodeVal, 0, len(paths))
	for _, p := range paths {
		nodes = append(nodes, &nodeVal{kind: "ChangedFile", text: p})
	}
	return &nodeVal{kind: "ChangedFileConnection", nodes: nodes, hasNext: hasNext}
}

func (c *gqlCtx) findRepoByID(id int64) *Repo {
	for _, r := range c.a.store.ListRepos(c.a.store.ViewerLogin()) {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (c *gqlCtx) findIssueByID(id int64) (*Repo, *Issue) {
	for _, r := range c.a.store.ListRepos(c.a.store.ViewerLogin()) {
		for _, iss := range c.a.store.ListIssues(r, "") {
			if iss.ID == id {
				return r, iss
			}
		}
	}
	return nil, nil
}

func (c *gqlCtx) findPullByID(id int64) (*Repo, *Pull) {
	for _, r := range c.a.store.ListRepos(c.a.store.ViewerLogin()) {
		c.a.store.mu.RLock()
		var found *Pull
		for _, pr := range r.Pulls {
			if pr.ID == id {
				found = pr
				break
			}
		}
		c.a.store.mu.RUnlock()
		if found != nil {
			return r, found
		}
	}
	return nil, nil
}

func (c *gqlCtx) nodeByID(raw string) *nodeVal {
	kind, id, ok := decodeNodeID(raw)
	if !ok {
		return nil
	}
	switch kind {
	case "Repository":
		if r := c.findRepoByID(id); r != nil {
			return c.repoNode(r)
		}
	case "Issue":
		if _, iss := c.findIssueByID(id); iss != nil {
			return c.issueNode(iss)
		}
	case "PullRequest":
		if _, pr := c.findPullByID(id); pr != nil {
			return c.pullNode(pr)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Root execution and mutations
// ---------------------------------------------------------------------------

func (c *gqlCtx) execRoot(op *gqlOp, vars map[string]any) map[string]any {
	data := map[string]any{}
	if op.kind == "mutation" {
		for _, sel := range op.sels {
			if sel.frag {
				continue
			}
			data[selKey(sel)] = c.execMutation(sel, vars)
		}
		return data
	}
	for _, sel := range op.sels {
		if sel.frag {
			continue
		}
		key := selKey(sel)
		switch sel.name {
		case "viewer":
			data[key] = c.resolveNode(c.viewerUser(), sel.children, vars)
		case "repository":
			args := argMap(sel, vars)
			r := c.a.store.GetRepo(argStr(args, "owner"), argStr(args, "name"))
			if r == nil {
				data[key] = nil
			} else {
				data[key] = c.resolveNode(c.repoNode(r), sel.children, vars)
			}
		case "node":
			args := argMap(sel, vars)
			node := c.nodeByID(argStr(args, "id"))
			if node == nil {
				data[key] = nil
			} else {
				data[key] = c.resolveNode(node, sel.children, vars)
			}
		case "__type":
			args := argMap(sel, vars)
			name := argStr(args, "name")
			if _, ok := gqlTypeFields[name]; ok {
				data[key] = c.resolveNode(&nodeVal{kind: "Type", typeName: name}, sel.children, vars)
			} else if _, ok := gqlTypeEnums[name]; ok {
				data[key] = c.resolveNode(&nodeVal{kind: "Type", typeName: name}, sel.children, vars)
			} else {
				data[key] = nil
			}
		default:
			c.unknownField(sel.name, "Query")
		}
	}
	return data
}

func inputObj(sel *gqlSel, vars map[string]any) map[string]any {
	args := argMap(sel, vars)
	if in, ok := args["input"].(map[string]any); ok {
		return in
	}
	return map[string]any{}
}

func (c *gqlCtx) execMutation(sel *gqlSel, vars map[string]any) any {
	in := inputObj(sel, vars)
	switch sel.name {
	case "createIssue":
		kind, repoID, ok := decodeNodeID(argStr(in, "repositoryId"))
		if !ok || kind != "Repository" {
			c.addErr("createIssue: repositoryId is not a repository id")
			return nil
		}
		r := c.findRepoByID(repoID)
		if r == nil {
			c.addErr("createIssue: repository not found")
			return nil
		}
		iss, err := c.a.store.CreateIssue(r, argStr(in, "title"), argStr(in, "body"), nil)
		if err != nil {
			c.addErr("createIssue: " + err.Error())
			return nil
		}
		return c.resolveNode(&nodeVal{kind: "CreateIssuePayload", issue: iss}, sel.children, vars)
	case "closeIssue":
		kind, issueID, ok := decodeNodeID(argStr(in, "issueId"))
		if !ok || kind != "Issue" {
			c.addErr("closeIssue: issueId is not an issue id")
			return nil
		}
		r, iss := c.findIssueByID(issueID)
		if iss == nil {
			c.addErr("closeIssue: issue not found")
			return nil
		}
		closed, ok := c.a.store.CloseIssue(r, iss.Number)
		if !ok || closed == nil {
			c.addErr("closeIssue: issue not found")
			return nil
		}
		return c.resolveNode(&nodeVal{kind: "CloseIssuePayload", issue: closed}, sel.children, vars)
	case "addComment":
		kind, issueID, ok := decodeNodeID(argStr(in, "subjectId"))
		if !ok || kind != "Issue" {
			c.addErr("addComment: subjectId is not an issue id")
			return nil
		}
		r, iss := c.findIssueByID(issueID)
		if iss == nil {
			c.addErr("addComment: issue not found")
			return nil
		}
		body := argStr(in, "body")
		count, ok := c.a.store.AddComment(r, iss.Number, body)
		if !ok {
			c.addErr("addComment: issue not found")
			return nil
		}
		restRecordComment(r.Owner, r.Name, iss.Number, count, body)
		commentID := encodeOpaque("IssueComment:" + strconv.FormatInt(iss.ID, 10) + ":" + strconv.Itoa(count))
		return c.resolveNode(&nodeVal{kind: "AddCommentPayload", commentID: commentID, commentBody: body}, sel.children, vars)
	case "createPullRequest":
		kind, repoID, ok := decodeNodeID(argStr(in, "repositoryId"))
		if !ok || kind != "Repository" {
			c.addErr("createPullRequest: repositoryId is not a repository id")
			return nil
		}
		r := c.findRepoByID(repoID)
		if r == nil {
			c.addErr("createPullRequest: repository not found")
			return nil
		}
		pr, err := c.a.store.CreatePull(r, argStr(in, "title"), argStr(in, "headRefName"), argStr(in, "baseRefName"), argStr(in, "body"))
		if err != nil {
			c.addErr("createPullRequest: " + err.Error())
			return nil
		}
		return c.resolveNode(&nodeVal{kind: "CreatePullRequestPayload", pull: pr}, sel.children, vars)
	case "mergePullRequest":
		kind, pullID, ok := decodeNodeID(argStr(in, "pullRequestId"))
		if !ok || kind != "PullRequest" {
			c.addErr("mergePullRequest: pullRequestId is not a pull request id")
			return nil
		}
		r, pr := c.findPullByID(pullID)
		if pr == nil {
			c.addErr("mergePullRequest: pull request not found")
			return nil
		}
		if _, err := c.a.store.MergePull(r, pr.Number); err != nil {
			c.addErr("mergePullRequest: " + err.Error())
			return nil
		}
		fresh := c.a.store.GetPull(r, pr.Number)
		if fresh == nil {
			fresh = pr
		}
		return c.resolveNode(&nodeVal{kind: "MergePullRequestPayload", pull: fresh}, sel.children, vars)
	default:
		c.unknownField(sel.name, "Mutation")
		return nil
	}
}

func (c *gqlCtx) execOne(body map[string]any) map[string]any {
	query, _ := body["query"].(string)
	vars := map[string]any{}
	if rawVars, ok := body["variables"].(map[string]any); ok {
		vars = rawVars
	}
	ops, err := gqlParseDocument(query)
	if err != nil {
		return map[string]any{"data": nil, "errors": []map[string]any{{"message": err.Error()}}}
	}
	op := ops[0]
	if name, ok := body["operationName"].(string); ok && name != "" {
		for _, cand := range ops {
			if cand.name == name {
				op = cand
				break
			}
		}
	}
	data := c.execRoot(op, vars)
	resp := map[string]any{"data": data}
	if len(c.errs) > 0 {
		resp["errors"] = c.errs
	}
	return resp
}

func (a *App) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	if !a.requireAuth(w, r) {
		return
	}
	raw := BodyBytes(r)
	if len(raw) == 0 {
		WriteError(w, http.StatusBadRequest, "request body must be JSON")
		return
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		WriteError(w, http.StatusBadRequest, "request body must be JSON")
		return
	}
	switch body := parsed.(type) {
	case map[string]any:
		ctx := &gqlCtx{a: a}
		WriteJSON(w, http.StatusOK, ctx.execOne(body))
	case []any:
		out := make([]any, 0, len(body))
		for _, entry := range body {
			opBody, ok := entry.(map[string]any)
			if !ok {
				out = append(out, map[string]any{"data": nil, "errors": []map[string]any{{"message": "each batched operation must be an object"}}})
				continue
			}
			ctx := &gqlCtx{a: a}
			out = append(out, ctx.execOne(opBody))
		}
		WriteJSON(w, http.StatusOK, out)
	default:
		WriteError(w, http.StatusBadRequest, "request body must be JSON")
	}
}
