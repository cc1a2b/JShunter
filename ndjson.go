package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// outputNDJSON streams the dedupe-table snapshot one finding per line. Stable
// ordering: severity desc, then confidence desc, then name. This is the
// preferred shape for `jq -c`, `mlr`, and SIEM ingestion paths.
func outputNDJSON() {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	for _, f := range flushFindings() {
		if err := enc.Encode(f); err != nil {
			fmt.Fprintf(os.Stderr, "[ndjson] encode: %v\n", err)
			return
		}
	}
}
