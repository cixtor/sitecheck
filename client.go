package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Scanner holds the metadata for the malware scan procedure, including the
// original URL requested by the user, some optional parameters for the HTTP
// request and the JSON-decoded data obtained from the scan results.
type Scanner struct {
	Domain    string
	FromCache bool
	Report    Result
}

// Result contains the JSON-decoded data from the API call.
type Result struct {
	Scan            map[string][]string `json:"SCAN"`
	Version         map[string][]string `json:"VERSION"`
	System          map[string][]string `json:"SYSTEM"`
	Links           map[string][]string `json:"LINKS"`
	Recommendations [][]string          `json:"RECOMMENDATIONS"`
	OutdatedScan    [][]string          `json:"OUTDATEDSCAN"`
	Blacklist       InfoWarning         `json:"BLACKLIST"`
	Malware         InfoWarning         `json:"MALWARE"`
	WebApp          Application         `json:"WEBAPP"`
}

// Application contains details for the scan results.
type Application struct {
	Info    [][]string `json:"INFO"`
	Warn    []string   `json:"WARN"`
	Version []string   `json:"VERSION"`
	Notice  []string   `json:"NOTICE"`
}

// InfoWarning contains details for the scan results.
type InfoWarning struct {
	Info [][]string `json:"INFO"`
	Warn [][]string `json:"WARN"`
}

// NewScanner returns an instance of the program with a new domain.
func NewScanner(domain string) *Scanner {
	return &Scanner{Domain: domain}
}

// URL builds and returns the URL for the API calls.
func (s *Scanner) URL() string {
	urlStr := service

	urlStr += "?json=1"
	urlStr += "&fromwp=2"

	if !s.FromCache {
		/* get fresh results */
		urlStr += "&clear=1"
	}

	urlStr += "&scan=" + s.Domain

	return urlStr
}

// UseCachedResults forces the scanner to retrieve cached results.
func (s *Scanner) UseCachedResults() {
	s.FromCache = true
}

// Request builds and sends the HTTP request to the API service.
func (s *Scanner) Request() (io.Reader, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", s.URL(), nil)

	if err != nil {
		return nil, err
	}

	req.Header.Add("DNT", "1")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept-Language", "end-US,en")
	req.Header.Set("User-Agent", "Mozilla/5.0 (KHTML, like Gecko) Safari/537.36")

	resp, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var buf bytes.Buffer
	(&buf).ReadFrom(resp.Body)

	return &buf, nil
}

// Scan executes the HTTP request, reads and decodes the scan results.
func (s *Scanner) Scan(export bool) error {
	reader, err := s.Request()

	if err != nil {
		return err
	}

	if export {
		fmt.Println(reader)
		return nil
	}

	return json.NewDecoder(reader).Decode(&s.Report)
}

// Justify formats the output of the scan results into human readable blocks.
func (s *Scanner) Justify(text string) string {
	var final string
	var counter int

	chunk := 97 /* maximum width per line */
	lines := 10 /* maximum number of lines */
	limit := lines * chunk

	text = strings.Replace(text, "\n", "", -1)
	text = strings.Replace(text, "\t", "", -1)
	text = strings.Replace(text, "\r", "", -1)

	if len(text) > limit {
		text = text[0:limit] + "..."
	}

	for _, char := range text {
		if counter == 0 {
			final += "\x20\x20\x20"
		}

		final += string(char)
		counter++

		if counter >= chunk {
			final += "\n"
			counter = 0
		}
	}

	final += "\n"

	return final
}

// Print writes to io.Writer the scan results.
func (s *Scanner) Print(export bool) {
	if export {
		return
	}

	fmt.Println("\033[48;5;008m @ Website Information \033[0m")
	for key, value := range s.Report.Scan {
		fmt.Printf(" \033[1;95m%s:\033[0m %s\n", key, strings.Join(value, ",\x20"))
	}
	for _, values := range s.Report.System {
		for _, value := range values {
			fmt.Printf(" \033[0;2m%s\033[0m\n", value)
		}
	}

	if len(s.Report.WebApp.Warn) > 0 ||
		len(s.Report.WebApp.Info) > 0 ||
		len(s.Report.WebApp.Version) > 0 ||
		len(s.Report.WebApp.Notice) > 0 {
		fmt.Println()
		fmt.Println("\033[48;5;008m @ Application Details \033[0m")
		for _, value := range s.Report.WebApp.Warn {
			fmt.Printf(" %s\n", value)
		}
		for _, values := range s.Report.WebApp.Info {
			fmt.Printf(" %s \033[0;2m%s\033[0m\n", values[0], values[1])
		}
		for _, value := range s.Report.WebApp.Version {
			fmt.Printf(" %s\n", value)
		}
		for _, value := range s.Report.WebApp.Notice {
			fmt.Printf(" %s\n", value)
		}
	}

	// Print security recommendations.
	if len(s.Report.Recommendations) > 0 {
		fmt.Println()
		fmt.Println("\033[48;5;068m @ Recommendations \033[0m")
		for _, values := range s.Report.Recommendations {
			fmt.Print(" \033[0;94m\u2022\033[0m")
			fmt.Print(" \033[0;1m" + values[0] + "\033[0m\n")
			fmt.Print("   " + values[1] + "\n")
			fmt.Print("   " + values[2] + "\n")
		}
	}

	// Print outdated software information.
	if len(s.Report.OutdatedScan) > 0 {
		fmt.Println()
		fmt.Println("\033[48;5;068m @ OutdatedScan \033[0m")
		for _, values := range s.Report.OutdatedScan {
			fmt.Printf(" \033[0;94m\u2022\033[0m %s\n", values[0])
			fmt.Printf("   %s\n", values[1])
			fmt.Printf("   %s\n", values[2])
		}
	}

	// Print links, iframes, and local/external javascript files.
	for key, values := range s.Report.Links {
		fmt.Println()
		fmt.Printf("\033[48;5;097m @ Links %s \033[0m\n", key)
		for _, value := range values {
			fmt.Printf(" %s\n", value)
		}
	}

	// Print blacklist status information.
	if len(s.Report.Blacklist.Warn) > 0 || len(s.Report.Blacklist.Info) > 0 {
		fmt.Println()
		blacklistColor := "034"
		if len(s.Report.Blacklist.Warn) > 0 {
			blacklistColor = "161"
		}
		fmt.Printf("\033[48;5;%sm @ Blacklist Status \033[0m\n", blacklistColor)
		for _, values := range s.Report.Blacklist.Warn {
			fmt.Printf(" \033[0;91m\u2718\033[0m %s\n", values[0])
			fmt.Printf("   %s\n", values[1])
		}
		for _, values := range s.Report.Blacklist.Info {
			fmt.Printf(" \033[0;92m\u2714\033[0m %s\n", values[0])
			fmt.Printf("   %s\n", values[1])
		}
	}

	// Print malware payload information.
	if len(s.Report.Malware.Warn) > 0 {
		fmt.Println()
		fmt.Println("\033[48;5;161m @ Malware Payloads \033[0m")
		for _, values := range s.Report.Malware.Warn {
			fmt.Printf(" \033[0;91m\u2022\033[0m %s\n", values[0])
			fmt.Printf("%s", s.Justify(values[1]))
		}
	}
}
