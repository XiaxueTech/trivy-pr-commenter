package main

import (
	"bufio"
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
	// whatever

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
	var validCommentWritten bool
	for _, result := range trivyReport.Results {
		// skip non config/terraform results
		if result.Class != "config" && result.Type != "terraform" {
			fmt.Printf("%s / %s / %s - not a config/terraform result; skipping\n", result.Target, result.Type, result.Class)
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
			fmt.Printf("Preparing comment for violation of rule %v in %v (lines %v to %v)\n", misconfiguration.ID, filename, misconfiguration.CauseMetadata.StartLine, misconfiguration.CauseMetadata.EndLine)

			// Debugging: Print the content of the lines to verify if they correspond to the expected lines in the Terraform file
			printLines(filename, misconfiguration.CauseMetadata.StartLine, misconfiguration.CauseMetadata.EndLine)

			comment := generateErrorMessage(misconfiguration)
			err := c.WriteMultiLineComment(filename, comment, misconfiguration.CauseMetadata.StartLine, misconfiguration.CauseMetadata.EndLine)
			if err != nil {
				fmt.Println("  Ran into some kind of error")
				fmt.Println("    " + err.Error())
				switch err.(type) {
				case commenter.CommentAlreadyWrittenError:
					fmt.Println("  Ignoring - comment already written")
					validCommentWritten = true
				case commenter.CommentNotValidError:
					fmt.Println("  Ignoring - change not part of the current PR")
					continue
				default:
					errMessages = append(errMessages, err.Error())
				}
			} else {
				validCommentWritten = true
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

	if validCommentWritten || len(errMessages) == 0 {
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

func printLines(filename string, startLine, endLine int) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNo := 1
	for scanner.Scan() {
		if lineNo >= startLine && lineNo <= endLine {
			fmt.Printf("Line %d: %s\n", lineNo, scanner.Text())
		}
		if lineNo > endLine {
			break
		}
		lineNo++
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error scanning file: %v\n", err)
	}
}

func extractPullRequestNumber() (int, error) {
	prStr := os.Getenv("PR_NUMBER")
	if prStr == "" {
		return 0, fmt.Errorf("environment variable PR_NUMBER not set")
	}
	prNo, err := strconv.Atoi(prStr)
	if err != nil {
		return 0, fmt.Errorf("unable to convert PR_NUMBER to integer: %v", err)
	}
	return prNo, nil
}

func fail(message string) {
	fmt.Println("::error::" + message)
	os.Exit(1)
}
