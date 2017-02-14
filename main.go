package main

import (
	"flag"
	"fmt"
	"os"
)

const service = "https://sitecheck.sucuri.net/"

var website = flag.String("d", "", "Domain name or web application to scan")
var usecache = flag.Bool("c", false, "Recycle the results from a previous scan")
var export = flag.Bool("e", false, "Export scan results as a JSON encoded string")

func main() {
	flag.Usage = func() {
		fmt.Println("SiteCheck, Web Application Security Scanner")
		fmt.Println("  https://en.wikipedia.org/wiki/Web_application_security_scanner")
		fmt.Println("  https://github.com/cixtor/sitecheck")
		fmt.Println("  https://sitecheck.sucuri.net/")
		fmt.Println("  https://cixtor.com/")
		fmt.Println()
		fmt.Println("The malware scanner is a free tool powered by Sucuri SiteCheck,")
		fmt.Println("it will check your website for known malware, blacklisting status,")
		fmt.Println("website errors, and out-of-date software. Although we do our best")
		fmt.Println("to provide the best results, full accuracy is not realistic, and")
		fmt.Println("not guaranteed.")
		fmt.Println()
		fmt.Println("Usage:")
		flag.PrintDefaults()
		os.Exit(2)
	}

	flag.Parse()

	if *website == "" {
		fmt.Println("Invalid domain name or web application")
		os.Exit(1)
	}

	scanner := NewScanner(*website)

	if *usecache {
		scanner.UseCachedResults()
	}

	if err := scanner.Scan(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if *export {
		if err := scanner.Export(os.Stdout); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		return
	}

	scanner.Print()
}
