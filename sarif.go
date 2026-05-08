package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// SARIF 2.1.0 output. Lets JSHunter feed GitHub Code Scanning, Azure Defender,
// any other consumer that accepts the SARIF tool format. Spec:
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type SARIFEnvelope struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string                  `json:"id"`
	Name                 string                  `json:"name,omitempty"`
	ShortDescription     SARIFText               `json:"shortDescription"`
	FullDescription      *SARIFText              `json:"fullDescription,omitempty"`
	HelpURI              string                  `json:"helpUri,omitempty"`
	DefaultConfiguration *SARIFRuleConfiguration `json:"defaultConfiguration,omitempty"`
	Properties           map[string]string       `json:"properties,omitempty"`
}

type SARIFText struct {
	Text string `json:"text"`
}

type SARIFRuleConfiguration struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID              string                 `json:"ruleId"`
	Level               string                 `json:"level"`
	Message             SARIFText              `json:"message"`
	Locations           []SARIFLocation        `json:"locations"`
	PartialFingerprints map[string]string      `json:"partialFingerprints,omitempty"`
	Properties          map[string]interface{} `json:"properties,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// severityToSARIFLevel maps JSHunter severities to the four levels SARIF
// recognizes. Critical and High both become "error" because GitHub
// code-scanning treats anything below "error" as informational.
func severityToSARIFLevel(sev Severity) string {
	switch sev {
	case SevCritical, SevHigh:
		return "error"
	case SevMedium:
		return "warning"
	case SevLow:
		return "note"
	}
	return "none"
}

// ToSARIF converts the dedupe-table snapshot into a SARIF 2.1.0 envelope.
// One result per Location so downstream tools can highlight every occurrence
// rather than collapsing them under one finding.
func ToSARIF() *SARIFEnvelope {
	registerRules()
	driverRules := make([]SARIFRule, 0, len(rulesRegistry))
	for _, r := range rulesRegistry {
		driverRules = append(driverRules, SARIFRule{
			ID:               r.ID,
			Name:             r.Name,
			ShortDescription: SARIFText{Text: r.Name},
			DefaultConfiguration: &SARIFRuleConfiguration{
				Level: severityToSARIFLevel(r.Severity),
			},
			Properties: map[string]string{
				"provider":    r.Provider,
				"secret_type": r.SecretType,
				"severity":    string(r.Severity),
			},
		})
	}

	results := []SARIFResult{}
	for _, f := range flushFindings() {
		locs := f.Locations
		if len(locs) == 0 {
			locs = []Location{{Source: f.Source, Line: f.Line, Column: f.Column}}
		}
		for _, loc := range locs {
			region := &SARIFRegion{StartLine: loc.Line, StartColumn: loc.Column}
			if loc.Line == 0 && loc.Column == 0 {
				region = nil
			}
			results = append(results, SARIFResult{
				RuleID: f.RuleID,
				Level:  severityToSARIFLevel(f.Severity),
				Message: SARIFText{
					Text: fmt.Sprintf("%s detected (confidence=%.2f, verified=%v)", f.Name, f.Confidence, f.Verified),
				},
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: loc.Source},
						Region:           region,
					},
				}},
				// partialFingerprints lets GitHub Code Scanning persist
				// dismiss/suppress decisions across runs even when the
				// finding moves source/line. value_hash is stable per
				// secret value; ruleId+secretType disambiguates classes.
				PartialFingerprints: map[string]string{
					"jshunter/valueHash":      f.ValueHash,
					"jshunter/ruleSecretType": f.RuleID + ":" + f.SecretType,
				},
				Properties: map[string]interface{}{
					"confidence": f.Confidence,
					"verified":   f.Verified,
					"value_hash": f.ValueHash,
					"redacted":   f.Redacted,
					"entropy":    f.Entropy,
					"reasons":    f.Reasons,
				},
			})
		}
	}

	return &SARIFEnvelope{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           "JSHunter",
				Version:        version,
				InformationURI: "https://github.com/cc1a2b/jshunter",
				Rules:          driverRules,
			}},
			Results: results,
		}},
	}
}

// outputSARIF writes the envelope to stdout. Operators piping to a file via
// `jshunter ... --sarif > findings.sarif` get a clean JSON document.
func outputSARIF() {
	env := ToSARIF()
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sarif] marshal: %v\n", err)
		return
	}
	fmt.Println(string(b))
}
