package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) <= 1 {
		fmt.Println("Sucuri SiteCheck")
		fmt.Println("  http://cixtor.com/")
		fmt.Println("  https://sitecheck.sucuri.net/")
		fmt.Println("  https://github.com/cixtor/mamutools")
		fmt.Println("  https://en.wikipedia.org/wiki/Web_application_security_scanner")
		fmt.Println("Usage: sitecheck example.com")
		os.Exit(2)
	}

	var domain string = os.Args[1]
	var scanner SiteCheck
	var result Result

	fmt.Printf(" Sucuri SiteCheck\n")
	fmt.Printf(" https://sitecheck.sucuri.net/\n")
	fmt.Printf(" Scanning %s ...\n\n", domain)

	result = scanner.Data(domain)
	scanner.Print(result)

	os.Exit(0)
}
