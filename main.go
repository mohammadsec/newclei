package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

func getPRs(token string) []int {
	var result []int
	page := 1

	for {
		url := fmt.Sprintf("https://api.github.com/repos/projectdiscovery/nuclei-templates/pulls?state=open&per_page=100&page=%d", page)
		req, _ := http.NewRequest("GET", url, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}

		body := make([]byte, resp.ContentLength)
		_, _ = resp.Body.Read(body)
		resp.Body.Close()

		if strings.TrimSpace(string(body)) == "[]" {
			break
		}

		prs := gjson.Get(string(body), "#.number").Array()
		for _, v := range prs {
			result = append(result, int(v.Num))
		}
		page++
	}

	return result
}

func getFiles(pr int, token string, cves bool) gjson.Result {
	url := fmt.Sprintf("https://api.github.com/repos/projectdiscovery/nuclei-templates/pulls/%d/files", pr)
	req, _ := http.NewRequest("GET", url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	json := string(body)

	if cves {
		return gjson.Get(json, "#(filename%\"*cves*.yaml\")#.raw_url")
	}
	return gjson.Get(json, "#(filename%\"*.yaml\")#.raw_url")
}

func downloadFile(url string, folder string) {
	tokens := strings.Split(url, "/")
	filename := tokens[len(tokens)-1]
	path := folder + "/" + filename

	if _, err := os.Stat(path); err == nil {
		fmt.Println("[SKIP]", filename, "already exists")
		return
	}

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("[ERROR] Failed to download:", filename)
		return
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		fmt.Println("[ERROR] Cannot create file:", filename)
		return
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		fmt.Println("[ERROR] Cannot save file:", filename)
		return
	}

	fmt.Println("[DOWNLOADED]", filename)
}

func main() {
	var token string
	var cves bool
	var folder string

	flag.StringVar(&token, "token", "", "GitHub token to use")
	flag.BoolVar(&cves, "cves", false, "Download only CVE templates")
	flag.StringVar(&folder, "folder", "yaml_files", "Folder to save files")
	flag.Parse()

	// Create folder if not exists
	if _, err := os.Stat(folder); os.IsNotExist(err) {
		os.Mkdir(folder, 0755)
	}

	prs := getPRs(token)
	for _, pr := range prs {
		files := getFiles(pr, token, cves)
		for _, file := range files.Array() {
			downloadFile(file.String(), folder)
		}
	}
}
