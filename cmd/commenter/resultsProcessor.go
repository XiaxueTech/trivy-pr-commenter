package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type result struct {
	Target            string            `json:"Target"`
	Class             string            `json:"Class"`
	Type              string            `json:"Type"`
	MisconfSummary    *misconfSummary   `json:"MisconfSummary,omitempty"`
	Misconfigurations []misconfiguration `json:"Misconfigurations,omitempty"`
}

type misconfSummary struct {
	Successes  int `json:"Successes"`
	Failures   int `json:"Failures"`
	Exceptions int `json:"Exceptions"`
}

type misconfiguration struct {
	Type           string            `json:"Type"`
	ID             string            `json:"ID"`
	AVDID          string            `json:"AVDID"`
	Title          string            `json:"Title"`
	Description    string            `json:"Description"`
	Message        string            `json:"Message"`
	Query          string            `json:"Query"`
	Resolution     string            `json:"Resolution"`
	Severity       string            `json:"Severity"`
	PrimaryURL     string            `json:"PrimaryURL"`
	References     []string          `json:"References"`
	Status         string            `json:"Status"`
	Layer          map[string]string `json:"Layer"`
	CauseMetadata  causeMetadata     `json:"CauseMetadata"`
}

type causeMetadata struct {
	Resource string `json:"Resource"`
	Provider string `json:"Provider"`
	Service  string `json:"Service"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Code      code   `json:"Code"`
}

type code struct {
	Lines []line `json:"Lines"`
}

type line struct {
	Number      int    `json:"Number"`
	Content     string `json:"Content"`
	IsCause     bool   `json:"IsCause"`
	Annotation  string `json:"Annotation"`
	Truncated   bool   `json:"Truncated"`
	Highlighted string `json:"Highlighted"`
	FirstCause  bool   `json:"FirstCause"`
	LastCause   bool   `json:"LastCause"`
}

const resultsFile = "trivy_results.json"

func loadResultsFile() ([]result, error) {
	results := struct{ Results []result }{}

	file, err := ioutil.ReadFile(resultsFile)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(file, &results)
	if err != nil {
		return nil, err
	}
	return results.Results, nil
}
