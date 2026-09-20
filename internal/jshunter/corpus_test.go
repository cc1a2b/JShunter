package jshunter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The labelled corpus is the precision gate. Every fp_*.js file is real-shaped
// bundler output that contains no credential; every tp_*.js file contains values
// that must be reported. A change that trades recall for precision, or the
// reverse, shows up here rather than in the field.

const cp_dir = "testdata/corpus"

type cp_label struct {
	Expect      string   `json:"expect"`
	RuleIDs     []string `json:"rule_ids"`
	MinFindings int      `json:"min_findings"`
	Note        string   `json:"note"`
}

// cp_allowedFP names corpus files whose remaining findings are correct behaviour
// rather than defects, with the reason. The map is empty: the negative corpus
// reports nothing at all, and an entry here would be a deliberate concession.
var cp_allowedFP = map[string]struct {
	max    int
	reason string
}{}

func cp_loadLabels(t *testing.T) map[string]cp_label {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cp_dir, "labels.json"))
	if err != nil {
		t.Skipf("corpus labels unavailable: %v", err)
	}
	var labels map[string]cp_label
	if err := json.Unmarshal(raw, &labels); err != nil {
		t.Fatalf("corpus labels are not valid JSON: %v", err)
	}
	if len(labels) == 0 {
		t.Fatal("corpus labels are empty")
	}
	return labels
}

// cp_materialise reads a corpus file and substitutes its %%JSHTnnn%%
// placeholders for the sample values, yielding the bytes a scan would see in
// the field. An unresolved placeholder is a hard failure: a fixture silently
// scanning as literal "%%JSHT007%%" would make the gate meaningless.
func cp_materialise(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cp_dir, name))
	if err != nil {
		t.Fatalf("read corpus file: %v", err)
	}
	out := string(raw)
	for k, v := range cp_tokens {
		out = strings.ReplaceAll(out, "%%"+k+"%%", v)
	}
	if i := strings.Index(out, "%%JSHT"); i >= 0 {
		end := i + 12
		if end > len(out) {
			end = len(out)
		}
		t.Fatalf("%s has an unresolved placeholder %q; add it to cp_tokens", name, out[i:end])
	}
	return []byte(out)
}

// cp_scan runs one corpus file through the curated registry at the shipping
// threshold and returns the rule ids reported.
func cp_scan(t *testing.T, name string) []string {
	t.Helper()
	body := cp_materialise(t, name)
	resetFindings()
	var ids []string
	for _, f := range analyzeBody("corpus://"+name, body, DefaultMinConfidence) {
		ids = append(ids, f.RuleID)
	}
	sort.Strings(ids)
	return ids
}

func cp_withDefaults(t *testing.T) {
	t.Helper()
	prevPublic, prevFloor, prevGate := reportPublicExposure, minSeverityFloor, structuralGateEnabled
	reportPublicExposure, minSeverityFloor, structuralGateEnabled = false, 0, true
	t.Cleanup(func() {
		reportPublicExposure, minSeverityFloor, structuralGateEnabled = prevPublic, prevFloor, prevGate
		resetFindings()
	})
}

func TestCorpus_NegativesStayQuiet(t *testing.T) {
	cp_withDefaults(t)
	labels := cp_loadLabels(t)

	total := 0
	for name, label := range labels {
		if label.Expect != "none" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ids := cp_scan(t, name)
			total += len(ids)
			allowed := 0
			if a, ok := cp_allowedFP[name]; ok {
				allowed = a.max
			}
			if len(ids) > allowed {
				t.Errorf("reported %d findings %v, allowance is %d\nnote: %s", len(ids), ids, allowed, label.Note)
			}
		})
	}
	t.Logf("negative corpus reported %d findings in total", total)
}

func TestCorpus_PositivesStillFire(t *testing.T) {
	cp_withDefaults(t)
	labels := cp_loadLabels(t)

	for name, label := range labels {
		if label.Expect != "some" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			ids := cp_scan(t, name)
			if len(ids) < label.MinFindings {
				t.Errorf("reported %d findings %v, want at least %d", len(ids), ids, label.MinFindings)
			}
			for _, want := range label.RuleIDs {
				if !ev_has(ids, want) {
					t.Errorf("rule %q did not fire; got %v", want, ids)
				}
			}
		})
	}
}

// TestCorpus_EveryFileIsLabelled keeps the corpus and its labels in step, so a
// file added without a label cannot silently escape the gate.
func TestCorpus_EveryFileIsLabelled(t *testing.T) {
	labels := cp_loadLabels(t)
	files, err := filepath.Glob(filepath.Join(cp_dir, "*.js"))
	if err != nil {
		t.Fatalf("glob corpus: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("corpus contains no JavaScript files")
	}
	for _, f := range files {
		name := filepath.Base(f)
		if _, ok := labels[name]; !ok {
			t.Errorf("corpus file %q has no entry in labels.json", name)
		}
	}
	for name := range labels {
		if _, err := os.Stat(filepath.Join(cp_dir, name)); err != nil {
			t.Errorf("labels.json names %q, which is not in the corpus", name)
		}
	}
}

// TestCorpus_StructuralGateIsWhatSuppresses proves the precision comes from the
// structural engine rather than from a threshold: with the gate off, the
// negative corpus reports substantially more.
func TestCorpus_StructuralGateIsWhatSuppresses(t *testing.T) {
	labels := cp_loadLabels(t)

	count := func(gate bool) int {
		prevPublic, prevFloor, prevGate := reportPublicExposure, minSeverityFloor, structuralGateEnabled
		reportPublicExposure, minSeverityFloor, structuralGateEnabled = !gate, 0, gate
		defer func() {
			reportPublicExposure, minSeverityFloor, structuralGateEnabled = prevPublic, prevFloor, prevGate
			resetFindings()
		}()
		n := 0
		for name, label := range labels {
			if label.Expect != "none" {
				continue
			}
			n += len(cp_scan(t, name))
		}
		return n
	}

	with, without := count(true), count(false)
	if with >= without {
		t.Errorf("negative corpus reported %d findings with the gate and %d without; the gate is not doing the work", with, without)
	}
	t.Logf("negative corpus: %d findings with the structural gate, %d without", with, without)
}
