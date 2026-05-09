package jshunter

import (
	"encoding/json"
	"fmt"
	"os"
)

// DiffPrevious reads a previous schema-v2 envelope and returns the set of
// value_hashes already reported. Operators run:
//
//	jshunter ... -j -o yesterday.json
//	jshunter ... --diff yesterday.json -j -o today-new.json
//
// and only see findings that weren't there yesterday. Anchored on
// value_hash because secrets that move between sources or that match
// different rules across releases must still dedupe consistently.
func DiffPrevious(path string) (map[string]bool, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read previous: %w", err)
	}
	var env struct {
		SchemaVersion int       `json:"schema_version"`
		Findings      []Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("parse previous: %w", err)
	}
	if env.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("--diff requires schema_version=%d; previous file has %d", SchemaVersion, env.SchemaVersion)
	}
	seen := make(map[string]bool, len(env.Findings))
	for _, f := range env.Findings {
		if f.ValueHash != "" {
			seen[f.ValueHash] = true
		}
	}
	return seen, nil
}
