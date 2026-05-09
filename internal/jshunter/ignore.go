package jshunter

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// .jshunterignore is the operator's permanent suppression list. Format is
// one entry per line, blank/`#` lines ignored. Supported kinds:
//
//	hash:<value_hash_hex>           # suppress one specific finding
//	rule:<rule_id|rule_id_glob>     # suppress an entire rule (or family)
//	source:<glob>                   # suppress all findings whose source matches
//	rule_value:<rule>:<value_glob>  # suppress findings where rule matches and
//	                                # value matches the glob (after rule)
//
// Globs use the standard filepath.Match syntax (`*`, `?`, `[abc]`).

type IgnoreEntry struct {
	Kind string
	A    string
	B    string
}

type IgnoreList struct {
	Entries []IgnoreEntry
}

// LoadIgnoreFile reads and parses an ignore file. A missing file is NOT an
// error — operators expect to run with or without one — but a malformed
// file is, because silently ignoring bad rules invites "why didn't my
// suppression work?" tickets.
func LoadIgnoreFile(path string) (*IgnoreList, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open ignore file: %w", err)
	}
	defer f.Close()
	return parseIgnoreReader(f)
}

func parseIgnoreReader(r io.Reader) (*IgnoreList, error) {
	il := &IgnoreList{}
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx == -1 {
			return nil, fmt.Errorf("ignore line %d: missing ':' separator", lineNo)
		}
		kind := strings.TrimSpace(line[:idx])
		rest := strings.TrimSpace(line[idx+1:])
		if rest == "" {
			return nil, fmt.Errorf("ignore line %d: empty value", lineNo)
		}
		switch kind {
		case "hash", "rule", "source":
			il.Entries = append(il.Entries, IgnoreEntry{Kind: kind, A: rest})
		case "rule_value":
			parts := strings.SplitN(rest, ":", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return nil, fmt.Errorf("ignore line %d: rule_value needs <rule>:<value-glob>", lineNo)
			}
			il.Entries = append(il.Entries, IgnoreEntry{Kind: "rule_value", A: parts[0], B: parts[1]})
		default:
			return nil, fmt.Errorf("ignore line %d: unknown kind %q (want hash|rule|source|rule_value)", lineNo, kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return il, nil
}

// ShouldIgnore returns true if any entry matches this finding.
func (il *IgnoreList) ShouldIgnore(f *Finding) bool {
	if il == nil {
		return false
	}
	for _, e := range il.Entries {
		switch e.Kind {
		case "hash":
			if f.ValueHash == e.A {
				return true
			}
		case "rule":
			if f.RuleID == e.A || globMatch(e.A, f.RuleID) {
				return true
			}
		case "source":
			if globMatch(e.A, f.Source) {
				return true
			}
		case "rule_value":
			if (f.RuleID == e.A || globMatch(e.A, f.RuleID)) && globMatch(e.B, f.Value) {
				return true
			}
		}
	}
	return false
}

func globMatch(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	ok, _ := filepath.Match(pattern, s)
	return ok
}
