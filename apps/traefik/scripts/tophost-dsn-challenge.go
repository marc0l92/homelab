package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

var DEBUG = true

func getCredentialsFromEnv() (string, string, error) {
	file, err := os.Open(".env")
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var username, password string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "USERNAME=") {
			username = strings.TrimPrefix(line, "USERNAME=")
		} else if strings.HasPrefix(line, "PASSWORD=") {
			password = strings.TrimPrefix(line, "PASSWORD=")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}
	if username == "" || password == "" {
		return "", "", fmt.Errorf("USERNAME or PASSWORD not found in .env file")
	}
	return username, password, nil
}

type CookieJar struct {
	cookies map[string]*http.Cookie
}

func NewCookieJar() *CookieJar {
	return &CookieJar{cookies: make(map[string]*http.Cookie)}
}

func (cj *CookieJar) SetFromResponse(resp *http.Response) {
	for _, c := range resp.Cookies() {
		cj.cookies[c.Name] = c
	}
}

func (cj *CookieJar) CookieHeader() string {
	var pairs []string
	for _, c := range cj.cookies {
		pairs = append(pairs, c.Name+"="+c.Value)
	}
	return strings.Join(pairs, "; ")
}

func (cj *CookieJar) PrintCookies(context string) {
	if DEBUG {
		fmt.Printf("[DEBUG] Cookies after %s: ", context)
		for _, c := range cj.cookies {
			fmt.Printf("%s=%s; ", c.Name, c.Value)
		}
		fmt.Println()
	}
}

func login(client *http.Client, cj *CookieJar, username, password string) error {
	url := "https://cp.tophost.it/x-login"
	data := fmt.Sprintf("user=%s&pass=%s", username, password)
	request, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	cj.SetFromResponse(resp)
	cj.PrintCookies("login")

	if DEBUG {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("[DEBUG] login response: %s\n", string(body))
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("login failed, status code: %d", resp.StatusCode)
	}
	return nil
}

func addTXTRecord(client *http.Client, cj *CookieJar, username, dnsTxtName, dnsTxtValue string) error {
	url := "https://cp.tophost.it/x-dns-add"
	data := fmt.Sprintf("name=%s&type=TXT&value=%s", dnsTxtName, dnsTxtValue)
	request, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Cookie", cj.CookieHeader())

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	cj.SetFromResponse(resp)
	cj.PrintCookies("addTXTRecord")

	if DEBUG {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("[DEBUG] addTXTRecord response: %s\n", string(body))
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("add TXT record failed, status code: %d", resp.StatusCode)
	}
	return nil
}

func deleteTXTRecord(client *http.Client, cj *CookieJar, recordId string) error {
	url := "https://cp.tophost.it/x-dns-del"
	data := fmt.Sprintf("record=%s", recordId)
	request, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Cookie", cj.CookieHeader())

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	cj.SetFromResponse(resp)
	cj.PrintCookies("deleteTXTRecord")

	if DEBUG {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("[DEBUG] deleteTXTRecord response: %s\n", string(body))
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("delete TXT record failed, status code: %d", resp.StatusCode)
	}
	return nil
}

func getDNSRecordID(client *http.Client, cj *CookieJar, dnsTxtName string) (string, error) {
	url := "https://cp.tophost.it/dns"
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Cookie", cj.CookieHeader())

	resp, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if DEBUG {
		// fmt.Printf("[DEBUG] getDNSRecordID response: %s\n", string(body))
	}

	// Find the table with id="dns-norm"
	tableRe := regexp.MustCompile(`<table[^>]*id=["']dns-norm["'][^>]*>(.*?)<\/table>`) // get the table body
	tableMatch := tableRe.FindSubmatch(body)
	if tableMatch == nil {
		return "", fmt.Errorf("dns-norm table not found")
	}
	tableBody := tableMatch[1]

	// Find all <tr id=tr-...>...</tr> blocks
	trRe := regexp.MustCompile(`<tr id=tr-([a-z0-9]+)>.*?</tr>`) // get all rows
	trs := trRe.FindAllSubmatch(tableBody, -1)
	for _, tr := range trs {
		rowID := string(tr[1])
		rowHTML := tr[0]
		// Find all <td ...>...</td> in the row
		tdRe := regexp.MustCompile(`<td[^>]*>(.*?)</td>`) // get all tds
		tds := tdRe.FindAllSubmatch(rowHTML, -1)
		if len(tds) > 0 {
			// Remove HTML tags and trim spaces from the first td
			name := regexp.MustCompile(`<[^>]+>`).ReplaceAllString(string(tds[0][1]), "")
			if strings.TrimSpace(name) == dnsTxtName {
				return rowID, nil
			}
		}
	}
	return "", fmt.Errorf("record with name %s not found", dnsTxtName)
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: <program> <action> <dnsTxtName> <dnsTxtValue>")
		os.Exit(1)
	}
	action := os.Args[1]
	dnsTxtName := os.Args[2]
	dnsTxtValue := os.Args[3]

	username, password, err := getCredentialsFromEnv()
	if err != nil {
		fmt.Printf("Error reading credentials: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{}
	cj := NewCookieJar()

	err = login(client, cj, username, password)
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		os.Exit(1)
	}

	switch action {
	case "present":
		err = addTXTRecord(client, cj, username, dnsTxtName, dnsTxtValue)
		if err != nil {
			fmt.Printf("Error adding TXT record: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("TXT record added successfully.")
	case "cleanup":
		recordId, err := getDNSRecordID(client, cj, dnsTxtName)
		if err != nil {
			fmt.Printf("Error getting DNS record ID: %v\n", err)
			os.Exit(1)
		}
		err = deleteTXTRecord(client, cj, recordId)
		if err != nil {
			fmt.Printf("Error deleting TXT record: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("TXT record cleaned up successfully.")
	}
}
