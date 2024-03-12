package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"strconv"
	"strings"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/owenrumney/go-github-pr-commenter/commenter"
)

func main() {
	fmt.Println("Starting the github commenter")

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
	trivyReport, err := loadTrivyReport(reportPath)
	if err != nil {
		fail(fmt.Sprintf("failed to load trivy report: %s", err.Error()))
	}
	if len(trivyReport.Results) == 0 {
		fmt.Println("No results found in trivy report, exiting")
		os.Exit(0)
	}
	fmt.Printf("Trivy found %v issues\n", len(trivyReport.Results))

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
	validCommentWritten := make(map[string]bool)

	for _, result := range trivyReport.Results {
		// skip non config/terraform results
		if result.Class != "config" && result.Type != "terraform" {
			fmt.Printf("%s / %s / %s - not a config/terraform result; skipping", result.Target, result.Type, result.Class)
			continue
		}
		// skip if no misconfigurations
		if len(result.Misconfigurations) == 0 {
			fmt.Printf("%s / %s / %s - no misconfigurations; skipping\n", result.Target, result.Type, result.Class)
			continue
		}

		for _, misconfiguration := range result.Misconfigurations {
			filename := workingDir + strings.ReplaceAll(result.Target, workspacePath, "")
			filename = strings.TrimPrefix(filename, "./")
			comment := generateErrorMessage(misconfiguration)
			fmt.Printf("Preparing comment for violation of rule %v in %v (lines %v to %v)\n", misconfiguration.ID, filename, misconfiguration.CauseMetadata.StartLine, misconfiguration.CauseMetadata.EndLine)

			// check if a comment has already been written for this vulnerability
			if validCommentWritten[misconfiguration.ID] {
				fmt.Printf("Skipping comment for vulnerability %s, as it has already been commented on.\n", misconfiguration.ID)
				continue
			}

			// write a comment for the vulnerability
			err := c.WriteMultiLineComment(filename, comment, misconfiguration.CauseMetadata.StartLine, misconfiguration.CauseMetadata.EndLine)
			if err != nil {
				fmt.Println("  Ran into some kind of error")
				fmt.Println("    " + err.Error())
				switch err.(type) {
				case commenter.CommentAlreadyWrittenError:
					fmt.Println("  Ignoring - comment already written")
					validCommentWritten[misconfiguration.ID] = true
				case commenter.CommentNotValidError:
					fmt.Println("  Ignoring - change not part of the current PR")
					continue
				default:
					errMessages = append(errMessages, err.Error())
				}
			} else {
				validCommentWritten[misconfiguration.ID] = true
				fmt.Printf("  Comment written for violation of rule %v in %v\n", misconfiguration.ID, filename)
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

	if len(errMessages) == 0 {
		if softFail, ok := os.LookupEnv("INPUT_SOFT_FAIL_COMMENTER"); ok && strings.ToLower(softFail) == "true" {
			return
		}
		os.Exit(1)
	}
}

func loadTrivyReport(reportPath string) (trivyTypes.Report, error) {
	fmt.Println("Loading trivy report from " + reportPath)

	file, err := os.Open(reportPath)
	if err != nil {
		return trivyTypes.Report{}, err
	}
	defer file.Close()

	var report trivyTypes.Report
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&report)
	if err != nil {
		return trivyTypes.Report{}, err
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

func generateErrorMessage(misconf trivyTypes.DetectedMisconfiguration) string {
	return fmt.Sprintf(`:warning: trivy found a **%s** severity issue from rule `+"`%s`"+`:
> %s

More information available %s`,
		misconf.Severity, misconf.ID, misconf.Message, formatUrls(misconf.References))
}

func formatUrls(urls []string) string {
	urlList := ""
	for _, url := range urls {
		if urlList != "" {
			urlList += fmt.Sprintf(" and ")
		}
		urlList += fmt.Sprintf("[here](%s)", url)
	}
	return urlList
}

func extractPullRequestNumber() (int, error) {
	github_event_file := "/github/workflow/event.json"
	file, err := ioutil.ReadFile(github_event_file)
	if err != nil {
		fail(fmt.Sprintf("GitHub event payload not found in %s", github_event_file))
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
