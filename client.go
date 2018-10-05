package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// NewScanner returns an instance of the program with a new domain.
func NewScanner(domain string) *Scanner {
	return &Scanner{Domain: domain}
}

// URL builds and returns the URL for the API calls.
func (s *Scanner) URL() string {
	if s.FromCache {
		return service + "/api/v2/?json&scan=" + s.Domain
	}

	return service + "/api/v2/?json&clear&scan=" + s.Domain
}

// Request builds and sends the HTTP request to the API service.
func (s *Scanner) Request() (io.Reader, error) {
	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequest(http.MethodGet, s.URL(), nil)

	if err != nil {
		return nil, err
	}

	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Accept-Language", "end-US,en")
	req.Header.Add("User-Agent", "Mozilla/5.0 (KHTML, like Gecko) Safari/537.36")

	res, err := client.Do(req)

	if err != nil {
		return nil, err
	}

	defer func() {
		if err := res.Body.Close(); err != nil {
			fmt.Println("res.Body.Close", err)
		}
	}()

	var buf bytes.Buffer
	(&buf).ReadFrom(res.Body)

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

	return final + "\n"
}

// Print writes to io.Writer the scan results.
func (s *Scanner) Print(export bool) {
	if export {
		return
	}

	s.printWebsiteInformation()
	s.printApplicationDetails()
	s.printRecommendations()
	s.printOutdatedScan()
	s.printLinks()
	s.printBlacklistStatus()
	s.printMalwarePayloads()
}

func (s *Scanner) printWebsiteInformation() {
	fmt.Println("\033[48;5;008m @ Website Information \033[0m")

	fmt.Printf(" \033[1;95mSite:\033[0m %s\n", strings.Join(s.Report.Scan.Site, ",\x20"))
	fmt.Printf(" \033[1;95mDomain:\033[0m %s\n", strings.Join(s.Report.Scan.Domain, ",\x20"))
	fmt.Printf(" \033[1;95mIP:\033[0m %s\n", strings.Join(s.Report.Scan.IP, ",\x20"))
	fmt.Printf(" \033[1;95mCMS:\033[0m %s\n", strings.Join(s.Report.Scan.CMS, ",\x20"))

	if s.Report.Scan.WAF.HasSucuriWAF == 1 {
		fmt.Printf(" \033[1;95mFirewall:\033[0m Sucuri Firewall\n")
	} else if s.Report.Scan.WAF.HasWAF == 1 {
		fmt.Printf(" \033[1;95mFirewall:\033[0m Generic Firewall\n")
	} else {
		fmt.Printf(" \033[1;95mFirewall:\033[0m \033[0;91mNo\033[0m\n")
	}

	for _, values := range s.Report.System {
		for _, value := range values {
			fmt.Printf(" \033[0;2m%s\033[0m\n", value)
		}
	}
}

func (s *Scanner) printApplicationDetails() {
	if len(s.Report.WebApp.Warn) <= 0 &&
		len(s.Report.WebApp.Info) <= 0 &&
		len(s.Report.WebApp.Version) <= 0 &&
		len(s.Report.WebApp.Notice) <= 0 {
		return
	}

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

// PrintRecommendations print security recommendations.
func (s *Scanner) printRecommendations() {
	if len(s.Report.Recommendations) <= 0 {
		return
	}

	fmt.Println()
	fmt.Println("\033[48;5;068m @ Recommendations \033[0m")

	for _, values := range s.Report.Recommendations {
		fmt.Print(" \033[0;94m\u2022\033[0m")
		fmt.Print(" \033[0;1m" + values[0] + "\033[0m\n")
		fmt.Print("   " + values[1] + "\n")
		fmt.Print("   " + values[2] + "\n")
	}
}

// PrintOutdatedScan print outdated software information.
func (s *Scanner) printOutdatedScan() {
	if len(s.Report.OutdatedScan) <= 0 {
		return
	}

	fmt.Println()
	fmt.Println("\033[48;5;068m @ OutdatedScan \033[0m")

	for _, values := range s.Report.OutdatedScan {
		fmt.Printf(" \033[0;94m\u2022\033[0m %s\n", values[0])
		fmt.Printf("   %s\n", values[1])
		fmt.Printf("   %s\n", values[2])
	}
}

// PrintLinks print links, iframes, and local/external javascript files.
func (s *Scanner) printLinks() {
	for key, values := range s.Report.Links {
		fmt.Println()
		fmt.Printf("\033[48;5;097m @ Links %s \033[0m\n", key)

		for _, value := range values {
			fmt.Printf(" %s\n", value)
		}
	}
}

// PrintBlacklistStatus print blacklist status information.
func (s *Scanner) printBlacklistStatus() {
	if len(s.Report.Blacklist.Warn) <= 0 && len(s.Report.Blacklist.Info) <= 0 {
		return
	}

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

// PrintMalwarePayloads print malware payload information.
func (s *Scanner) printMalwarePayloads() {
	if len(s.Report.Malware.Warn) <= 0 {
		return
	}

	fmt.Println()
	fmt.Println("\033[48;5;161m @ Malware Payloads \033[0m")

	for _, values := range s.Report.Malware.Warn {
		fmt.Printf(" \033[0;91m\u2022\033[0m %s\n", values[0])
		fmt.Printf("%s", s.Justify(values[1]))
	}
}
