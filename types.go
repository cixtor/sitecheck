package main

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
	Scan            ResultScan          `json:"SCAN"`
	Version         ResultVersion       `json:"VERSION"`
	System          map[string][]string `json:"SYSTEM"`
	Links           map[string][]string `json:"LINKS"`
	Recommendations [][]string          `json:"RECOMMENDATIONS"`
	OutdatedScan    [][]string          `json:"OUTDATEDSCAN"`
	Blacklist       InfoWarning         `json:"BLACKLIST"`
	Malware         InfoWarning         `json:"MALWARE"`
	WebApp          Application         `json:"WEBAPP"`
}

// ResultScan contains the details for the scan target.
type ResultScan struct {
	Site   []string `json:"SITE"`
	Domain []string `json:"DOMAIN"`
	IP     []string `json:"IP"`
	CMS    []string `json:"CMS"`
	WAF    ScanWAF  `json:"WAF"`
}

// ScanWAF contains the details for the WAF status.
type ScanWAF struct {
	HasWAF       int `json:"HASWAF"`
	HasSucuriWAF int `json:"HASSUCURIWAF"`
}

// ResultVersion contains the details for the result version.
type ResultVersion struct {
	Version      []string `json:"VERSION"`
	BuildDate    []string `json:"BUILDDATE"`
	DatabaseDate []string `json:"DBDATE"`
	CompiledDate []string `json:"COMPILEDDATE"`
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
