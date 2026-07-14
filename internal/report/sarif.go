package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// Minimal SARIF 2.1.0 writer for GitHub Code Scanning compatibility.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri,omitempty"`
	Version        string      `json:"version,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	ShortDescription sarifText         `json:"shortDescription"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

func writeSARIF(out io.Writer, r Report) error {
	rulesIndex := map[string]int{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range r.Findings {
		if _, ok := rulesIndex[f.Rule]; !ok {
			rulesIndex[f.Rule] = len(rules)
			rules = append(rules, sarifRule{
				ID:               f.Rule,
				ShortDescription: sarifText{Text: f.Rule},
				Properties: map[string]string{
					"category": string(f.Category),
					"severity": string(f.Severity),
				},
			})
		}

		loc := sarifLocation{
			PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifArtifact{URI: f.File},
			},
		}
		if f.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{
				StartLine:   f.Line,
				StartColumn: f.Column,
			}
		}

		msg := f.Message
		if f.Snippet != "" {
			msg = fmt.Sprintf("%s | snippet: %s", msg, f.Snippet)
		}

		results = append(results, sarifResult{
			RuleID:    f.Rule,
			Level:     severityToSARIFLevel(f.Severity),
			Message:   sarifText{Text: msg},
			Locations: []sarifLocation{loc},
		})
	}

	doc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Tool,
				InformationURI: "https://github.com/GhanshyamJha05/Sentinel",
				Version:        r.Version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func severityToSARIFLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
