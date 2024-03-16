package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/owenrumney/go-github-pr-commenter/commenter"
)

type TrivyResult struct {
	Target            string          `json:"Target"`
	Class             string          `json:"Class"`
	Type              string          `json:"Type"`
	MisconfSummary    MisconfSummary  `json:"MisconfSummary,omitempty"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations,omitempty"`
}

type MisconfSummary struct {
	Successes  int `json:"Successes"`
	Failures   int `json:"Failures"`
	Exceptions int `json:"Exceptions"`
}

type Misconfiguration struct {
	Type           string         `json:"Type"`
	ID             string         `json:"ID"`
	Description    string         `json:"Description"`
	Severity       string         `json:"Severity"`
	PrimaryURL     string         `json:"PrimaryURL"`
	CauseMetadata  CauseMetadata `json:"CauseMetadata"`
}

type CauseMetadata struct {
	Resource  string `json:"Resource"`
	Provider  string `json:"Provider"`
	Service   string `json:"Service"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Code      struct {
		Lines []struct {
			Number      int    `json:"Number"`
			Content     string `json:"Content"`
			IsCause     bool   `json:"IsCause"`
			Annotation  string `json:"Annotation,omitempty"`
			Truncated   bool   `json:"Truncated"`
			Highlighted string `json:"Highlighted,omitempty"`
			FirstCause  bool   `json:"FirstCause"`
			LastCause   bool   `json:"LastCause"`
		} `json:"Lines"`
	} `json:"Code"`
	Occurrences []struct {
		Resource string `json:"Resource"`
		Filename string `json:"Filename"`
		Location struct {
			StartLine int `json:"StartLine"`
			EndLine   int `json:"EndLine"`
		} `json:"Location"`
	} `json:"Occurrences"`
}

func main() {
	fmt.Println("Starting the Trivy PR commenter")

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

	args := os.Args[1:]
	reportPath := "trivy_sample_report.json"
	if len(args) > 0 {
		reportPath = args[0]
	}
	vulnerabilities, err := loadTrivyReport(reportPath)
	if err != nil {
		fail(fmt.Sprintf("failed to load Trivy report: %s", err.Error()))
	}
	if len(vulnerabilities) == 0 {
		fmt.Println("No vulnerabilities found in Trivy report, exiting")
		os.Exit(0)
	}
	fmt.Printf("Trivy found %v vulnerabilities\n", len(vulnerabilities))

	c, err := createCommenter(token, owner, repo, prNo)
	if err != nil {
		fail(fmt.Sprintf("failed to create commenter: %s", err.Error()))
	}

	workspacePath := fmt.Sprintf("%s/", os.Getenv("GITHUB_WORKSPACE"))
	fmt.Printf("Working in GITHUB_WORKSPACE %s\n", workspacePath)

	workingDir := os.Getenv("INPUT_WORKING_DIRECTORY")
	if workingDir != "" {
		workingDir = strings.TrimPrefix(workingDir, "./")
		workingDir = strings.TrimSuffix(workingDir, "/") + "/"
	}

	var errMessages []string
	var validCommentWritten bool
	for _, result := range vulnerabilities {
		for _, misconf := range result.Misconfigurations {
			for _, occurrence := range misconf.CauseMetadata.Occurrences {
				filename := workingDir + strings.ReplaceAll(occurrence.Filename, workspacePath, "")
				filename = strings.TrimPrefix(filename, "./")
				comment := generateErrorMessage(misconf)
				fmt.Printf("Preparing comment for vulnerability ID %s in %s (lines %d to %d)\n", misconf.ID, filename, occurrence.Location.StartLine, occurrence.Location.EndLine)
				err := c.WriteMultiLineComment(filename, comment, occurrence.Location.StartLine, occurrence.Location.EndLine)
				if err != nil {
					fmt.Printf("Error while writing comment: %s\n", err.Error())
					errMessages = append(errMessages, err.Error())
				} else {
					validCommentWritten = true
					fmt.Printf("Comment written for vulnerability ID %s in %s\n", misconf.ID, filename)
				}
			}
		}
	}

	if len(errMessages) > 0 {
		fmt.Printf("There were %d errors:\n", len(errMessages))
		for _, err := range errMessages {
			fmt.Println(err)
		}
		os.Exit(1)
	}

	if validCommentWritten || len(errMessages) == 0 {
		if softFail, ok := os.LookupEnv("INPUT_SOFT_FAIL_COMMENTER"); ok && strings.ToLower(softFail) == "true" {
			return
		}
		os.Exit(1)
	}
}

func loadTrivyReport(reportPath string) ([]TrivyResult, error) {
	fmt.Println("Loading trivy report from " + reportPath)

	file, err := os.Open(reportPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var report []TrivyResult
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&report)
	if err != nil {
		return nil, err
	}

	fmt.Println("Trivy report loaded successfully")

	return report, nil
}

func createCommenter(token, owner, repo string, prNo int) (*commenter.Commenter, error) {
	var err error
	var c *commenter.Commenter

	githubApiUrl := os.Getenv("GITHUB_API_URL")
	if githubApiUrl == "" || githubApiUrl == "https://api.github.com" {
		c, err = commenter.NewCommenter(token, owner, repo, prNo)
	} else {
		url, err := url.Parse(githubApiUrl)
		if err == nil {
			enterpriseUrl := fmt.Sprintf("%s://%s", url.Scheme, url.Hostname())
			c, err = commenter.NewEnterpriseCommenter(token, enterpriseUrl, enterpriseUrl, owner, repo, prNo)
		}
	}

	return c, err
}

func generateErrorMessage(misconf Misconfiguration) string {
	return fmt.Sprintf(`:warning: Trivy found a **%s** severity vulnerability (ID: %s):
> %s

More information available at %s`,
		misconf.Severity, misconf.ID, misconf.Description, misconf.PrimaryURL)
}

func extractPullRequestNumber() (int, error) {
	githubEventFile := "/github/workflow/event.json"
	file, err := ioutil.ReadFile(githubEventFile)
	if err != nil {
		fail(fmt.Sprintf("GitHub event payload not found in %s", githubEventFile))
		return -1, err
	}

	var data interface{}
	err = json.Unmarshal(file, &data)
	if err != nil {
		return -1, err
	}
	payload := data.(map[string]interface{})

	prNumber, err := strconv.Atoi(fmt.Sprintf("%v", payload["number"]))
	if err != nil {
		return 0, fmt.Errorf("not a valid PR")
	}
	return prNumber, nil
}

func fail(err string) {
	fmt.Printf("Error: %s\n", err)
	os.Exit(-1)
}
