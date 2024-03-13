package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/owenrumney/go-github-pr-commenter/commenter"
)

// TrivyVulnerability represents a vulnerability found by Trivy
type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	References       []string `json:"References"`
}

// TrivyScanResult represents the result of a Trivy scan
type TrivyScanResult struct {
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

func main() {
	fmt.Println("Starting the GitHub commenter")

	token := os.Getenv("INPUT_GITHUB_TOKEN")
	if len(token) == 0 {
		fail("the INPUT_GITHUB_TOKEN has not been set")
	}

	githubRepository := os.Getenv("GITHUB_REPOSITORY")
	split := strings.Split(githubRepository, "/")
	if len(split) != 2 {
		fail(fmt.Sprintf("unexpected value for GITHUB_REPOSITORY. Expected <organisation/name>, found %v", split))
	}
	owner := split[0]
	repo := split[1]

	fmt.Printf("Working in repository %s\n", repo)

	prNo, err := extractPullRequestNumber()
	if err != nil {
		fmt.Println("Not a PR, nothing to comment on, exiting")
		return
	}
	fmt.Printf("Working in PR %v\n", prNo)

	results, err := loadTrivyScanResults()
	if err != nil {
		fail(fmt.Sprintf("failed to load Trivy scan results: %s", err.Error()))
	}

	if len(results.Vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found.")
		os.Exit(0)
	}
	fmt.Printf("Trivy found %v vulnerabilities\n", len(results.Vulnerabilities))

	c, err := createCommenter(token, owner, repo, prNo)
	if err != nil {
		fail(fmt.Sprintf("could not create commenter: %s", err.Error()))
	}

	var errMessages []string
	var validCommentWritten bool
	for _, vulnerability := range results.Vulnerabilities {
		comment := generateTrivyErrorMessage(vulnerability)
		fmt.Printf("Preparing comment for vulnerability %s\n", vulnerability.VulnerabilityID)
		err := c.WriteMultiLineComment(comment)
		if err != nil {
			// comment errors
			errMessages = append(errMessages, err.Error())
		} else {
			validCommentWritten = true
			fmt.Printf("Commenting for vulnerability %s\n", vulnerability.VulnerabilityID)
		}
	}

	if len(errMessages) > 0 {
		fmt.Printf("There were %d comment errors:\n", len(errMessages))
		for _, err := range errMessages {
			fmt.Println(err)
		}
		os.Exit(1)
	}

	if validCommentWritten {
		// comments were successfully written exit with success status
		os.Exit(0)
	} else {
		// no comments were written exit with failure status
		os.Exit(1)
	}
}

func loadTrivyScanResults() (TrivyScanResult, error) {
	fmt.Println("Loading Trivy scan results")

	reportPath := os.Getenv("INPUT_TRIVY_REPORT_PATH")
	if reportPath == "" {
		reportPath = "trivy_report.json" // Default Trivy report path
	}

	file, err := os.Open(reportPath)
	if err != nil {
		return TrivyScanResult{}, err
	}
	defer file.Close()

	var result TrivyScanResult
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&result)
	if err != nil {
		return TrivyScanResult{}, err
	}

	fmt.Println("Trivy scan results loaded successfully")

	return result, nil
}

func generateTrivyErrorMessage(vulnerability TrivyVulnerability) string {
	comment := fmt.Sprintf(`:warning: Trivy found a **%s** severity vulnerability (ID: %s) in %s:
> %s

More information: %s`,
		vulnerability.Severity, vulnerability.VulnerabilityID, vulnerability.PkgName,
		vulnerability.Description, strings.Join(vulnerability.References, "\n"))
	return comment
}

func createCommenter(token, owner, repo string, prNo int) (*commenter.Commenter, error) {
	c, err := commenter.NewCommenter(token, owner, repo, prNo)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func extractPullRequestNumber() (int, error) {
	githubEventFile := "/github/workflow/event.json"
	file, err := ioutil.ReadFile(githubEventFile)
	if err != nil {
		return -1, fmt.Errorf("GitHub event payload not found in %s", githubEventFile)
	}

	var data map[string]interface{}
	err = json.Unmarshal(file, &data)
	if err != nil {
		return -1, err
	}

	prNumber, ok := data["number"].(float64)
	if !ok {
		return 0, fmt.Errorf("not a valid PR")
	}
	return int(prNumber), nil
}

func fail(err string) {
	fmt.Printf("Error: %s\n", err)
	os.Exit(-1)
}
