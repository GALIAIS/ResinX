package node

import (
	"fmt"
	"regexp"
	"strings"
)

// RegexFilterScope defines which part of a node tag candidate is matched.
type RegexFilterScope string

const (
	RegexFilterScopeFull RegexFilterScope = "full"
	RegexFilterScopeName RegexFilterScope = "name"
	RegexFilterScopeTag  RegexFilterScope = "tag"
)

// CompiledRegexFilter is one compiled regex rule.
// A rule can contain multiple alternatives (OR) via `||`.
type CompiledRegexFilter struct {
	Scope   RegexFilterScope
	Exclude bool
	Any     []*regexp.Regexp
}

// CompileRegexFilters parses and compiles enhanced regex filter syntax.
//
// Supported syntax:
//   - default scope: `full` (matches "<subscriptionName>/<tag>")
//   - scoped prefixes: `full:`, `name:`, `tag:` (case-insensitive)
//   - exclude prefix: leading `!`
//   - OR alternatives in one rule: `a||b||c`
func CompileRegexFilters(filters []string) ([]CompiledRegexFilter, error) {
	compiled := make([]CompiledRegexFilter, 0, len(filters))
	for i, raw := range filters {
		rule, err := compileRegexFilterRule(raw)
		if err != nil {
			return nil, fmt.Errorf("regex_filters[%d]: %v", i, err)
		}
		compiled = append(compiled, rule)
	}
	return compiled, nil
}

// LegacyRegexFilters wraps plain regexp filters into full-scope include rules.
func LegacyRegexFilters(regexes []*regexp.Regexp) []CompiledRegexFilter {
	if len(regexes) == 0 {
		return nil
	}
	out := make([]CompiledRegexFilter, 0, len(regexes))
	for _, re := range regexes {
		if re == nil {
			continue
		}
		out = append(out, CompiledRegexFilter{
			Scope: RegexFilterScopeFull,
			Any:   []*regexp.Regexp{re},
		})
	}
	return out
}

type compiledCandidate struct {
	full string
	name string
	tag  string
}

func compileRegexFilterRule(raw string) (CompiledRegexFilter, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return CompiledRegexFilter{}, fmt.Errorf("must not be empty")
	}

	exclude := false
	if strings.HasPrefix(s, "!") {
		exclude = true
		s = strings.TrimSpace(strings.TrimPrefix(s, "!"))
		if s == "" {
			return CompiledRegexFilter{}, fmt.Errorf("exclude filter must include pattern")
		}
	}

	scope := RegexFilterScopeFull
	if idx := strings.IndexByte(s, ':'); idx > 0 {
		prefix := strings.TrimSpace(s[:idx])
		switch strings.ToLower(prefix) {
		case string(RegexFilterScopeFull):
			scope = RegexFilterScopeFull
			s = strings.TrimSpace(s[idx+1:])
		case string(RegexFilterScopeName):
			scope = RegexFilterScopeName
			s = strings.TrimSpace(s[idx+1:])
		case string(RegexFilterScopeTag):
			scope = RegexFilterScopeTag
			s = strings.TrimSpace(s[idx+1:])
		}
	}
	if s == "" {
		return CompiledRegexFilter{}, fmt.Errorf("pattern must not be empty")
	}

	parts := strings.Split(s, "||")
	regexes := make([]*regexp.Regexp, 0, len(parts))
	for altIdx, part := range parts {
		pattern := strings.TrimSpace(part)
		if pattern == "" {
			return CompiledRegexFilter{}, fmt.Errorf("alternative pattern at index %d must not be empty", altIdx)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return CompiledRegexFilter{}, fmt.Errorf("invalid regex: %v", err)
		}
		regexes = append(regexes, re)
	}

	return CompiledRegexFilter{
		Scope:   scope,
		Exclude: exclude,
		Any:     regexes,
	}, nil
}

func matchesCompiledRegexFilter(c compiledCandidate, f CompiledRegexFilter) bool {
	if len(f.Any) == 0 {
		return false
	}
	var target string
	switch f.Scope {
	case RegexFilterScopeName:
		target = c.name
	case RegexFilterScopeTag:
		target = c.tag
	default:
		target = c.full
	}
	for _, re := range f.Any {
		if re != nil && re.MatchString(target) {
			return true
		}
	}
	return false
}
