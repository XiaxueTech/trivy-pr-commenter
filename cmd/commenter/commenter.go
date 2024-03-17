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

func main() {
	fmt.Println("Starting the GitHub commenter")

	token := os.Getenv("INPUT_GITHUB_TOKEN")
	if len(token) == 0 {
		fail("the INPUT_GITHUB_TOKEN has not been set")
	}

	githubRepository := os.Getenv("GITHUB_REPOSITORY")
	split := strings.Split(githubRepository, "/")
	if len(split) != 2 {
		fail(fmt.Sprintf("unexpected value for GITHUB_REPOSITORY. Expected <organization/name>, found %v", split))
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

	results, err := loadResultsFile()
	if err != nil {
		fail(fmt.Sprintf("failed to load results. %s", err.Error()))
	}

	if len(results) == 0 {
		fmt.Println("No issues found.")
		os.Exit(0)
	}
	fmt.Printf("trivy found %v issues\n", len(results))

	c, err := createCommenter(token, owner, repo, prNo)
	if err != nil {
		fail(fmt.Sprintf("could not connect to GitHub (%s)", err.Error()))
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
	for _, result := range results {
		result.Range.Filename = workingDir + strings.ReplaceAll(result.Range.Filename, workspacePath, "")
		comment := generateErrorMessage(result.Misconfigurations[0]) // Pass the first misconfiguration
		fmt.Printf("Preparing comment for violation of rule %v in %v\n", result.Misconfigurations[0].ID, result.Range.Filename)
		err := c.WriteMultiLineComment(result.Range.Filename, comment, result.Misconfigurations[0].CauseMetadata.StartLine, result.Misconfigurations[0].CauseMetadata.EndLine)
		if err != nil {
			// don't error if it's simply that the comments aren't valid for the PR
			switch err.(type) {
			case commenter.CommentAlreadyWrittenError:
				fmt.Println("Ignoring - comment already written")
				validCommentWritten = true
			case commenter.CommentNotValidError:
				fmt.Println("Ignoring - change not part of the current PR")
				continue
			default:
				errMessages = append(errMessages, err.Error())
			}
		} else {
			validCommentWritten = true
			fmt.Printf("Commenting for %s to %s:%d:%d\n", result.Misconfigurations[0].Description, result.Range.Filename, result.Misconfigurations[0].CauseMetadata.StartLine, result.Misconfigurations[0].CauseMetadata.EndLine)
		}
	}

	if len(errMessages) > 0 {
		fmt.Printf("There were %d errors:\n", len(errMessages))
		for _, err := range errMessages {
			fmt.Println(err)
		}
		os.Exit(1)
	}
	if validCommentWritten || len(errMessages) > 0 {
		if softFail, ok := os.LookupEnv("INPUT_SOFT_FAIL_COMMENTER"); ok && strings.ToLower(softFail) == "true" {
			return
		}
		os.Exit(1)
	}
}

func createCommenter(token, owner, repo string, prNo int) (*commenter.Commenter, error) {
	var err error
	var c *commenter.Commenter

	githubAPIURL := os.Getenv("GITHUB_API_URL")
	if githubAPIURL == "" || githubAPIURL == "https://api.github.com" {
		c, err = commenter.NewCommenter(token, owner, repo, prNo)
	} else {
		u, err := url.Parse(githubAPIURL)
		if err == nil {
			enterpriseURL := fmt.Sprintf("%s://%s", u.Scheme, u.Hostname())
			c, err = commenter.NewEnterpriseCommenter(token, enterpriseURL, enterpriseURL, owner, repo, prNo)
		}
	}

	return c, err
}

func generateErrorMessage(misconf misconfiguration) string {
	return fmt.Sprintf(`:warning: trivy found a **%s** severity issue from rule `+"`%s`"+`:
> %s

More information available %s`,
		misconf.Severity, misconf.ID, misconf.Description, formatUrls(misconf.References))
}

func extractPullRequestNumber() (int, error) {
	githubEventFile := "/github/workflow/event.json"
	file, err := ioutil.ReadFile(githubEventFile)
	if err != nil {
		fail(fmt.Sprintf("GitHub event payload not found in %s", githubEventFile))
		return -1, err
	}

	var data map[string]interface{}
	err = json.Unmarshal(file, &data)
	if err != nil {
		return -1, err
	}

	prNumber, err := strconv.Atoi(fmt.Sprintf("%v", data["number"]))
	if err != nil {
		return 0, fmt.Errorf("not a valid PR")
	}
	return prNumber, nil
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

func fail(err string) {
	fmt.Printf("Error: %s\n", err)
	os.Exit(-1)
}
