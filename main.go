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

type TrivyVulnerability struct {
	Target       string   `json:"Target"`
	Type         string   `json:"Type"`
	ID           string   `json:"ID"`
	Title        string   `json:"Title"`
	Description  string   `json:"Description"`
	Severity     string   `json:"Severity"`
	PrimaryURL   string   `json:"PrimaryURL"`
	References   []string `json:"References"`
	Status       string   `json:"Status"`
	Layer        struct{} `json:"Layer"`
	CauseMetadata struct{} `json:"CauseMetadata"`
	Occurrences  []struct {
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
	for _, vuln := range vulnerabilities {
		for _, occurrence := range vuln.Occurrences {
			filename := workingDir + strings.ReplaceAll(occurrence.Filename, workspacePath, "")
			filename = strings.TrimPrefix(filename, "./")
			comment := generateErrorMessage(vuln)
			fmt.Printf("Preparing comment for vulnerability ID %s in %s (lines %d to %d)\n", vuln.ID, filename, occurrence.Location.StartLine, occurrence.Location.EndLine)
			err := c.WriteMultiLineComment(filename, comment, occurrence.Location.StartLine, occurrence.Location.EndLine)
			if err != nil {
				fmt.Printf("Error while writing comment: %s\n", err.Error())
				errMessages = append(errMessages, err.Error())
			} else {
				validCommentWritten = true
				fmt.Printf("Comment written for vulnerability ID %s in %s\n", vuln.ID, filename)
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

func loadTrivyReport(reportPath string) ([]TrivyVulnerability, error) {
	fmt.Println("Loading Trivy report from " + reportPath)

	file, err := os.Open(reportPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var vulnerabilities []TrivyVulnerability
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&vulnerabilities)
	if err != nil {
		return nil, err
	}

	fmt.Println("Trivy report loaded successfully")

	return vulnerabilities, nil
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

func generateErrorMessage(vuln TrivyVulnerability) string {
	return fmt.Sprintf(`:warning: Trivy found a **%s** severity vulnerability (ID: %s) in %s:
> %s

More information available at %s`,
		vuln.Severity, vuln.ID, vuln.Target, vuln.Description, vuln.PrimaryURL)
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
