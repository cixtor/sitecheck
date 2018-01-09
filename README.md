### SiteCheck, Web Application Security Scanner

> A web application security scanner is a program which communicates with a web application through the web front-end in order to identify potential security vulnerabilities in the web application and architectural weaknesses. It performs a black-box test. Unlike source code scanners, web application scanners don't have access to the source code and therefore detect vulnerabilities by actually performing attacks.
>
> Web applications have been highly popular since 2000 because they allow users to have an interactive experience on the Internet. Rather than just view static web pages, users are able to create personal accounts, add content, query databases and complete transactions. In the process of providing an interactive experience web applications frequently collect, store and use sensitive personal data to deliver their service.
>
> More info at [Web Application Security Scanner, Wikipedia](https://en.wikipedia.org/wiki/Web_application_security_scanner)

The malware scanner is a free tool powered by [Sucuri SiteCheck](https://sitecheck.sucuri.net), it checks your website for known malware, blacklisting status, website errors, and out-of-date software. Although the tool does its best to provide the best results, 100% accuracy is not realistic and not guaranteed. Note that the information returned by this tool will be kept available in the service for other people to see.

### Installation

```shell
go get -u github.com/cixtor/sitecheck
```

### Usage

Command                     | Description
----------------------------|-----------------------
sitecheck -help             | Shows this information
sitecheck -d example.com    | Executes a fresh web malware scan on the domain
sitecheck -d example.com -e | Executes and returns the malware scan results as JSON
sitecheck -d example.com -c | Executes and returns a cached version of the malware scan

**Note:** As of May, 2018 a fresh malware scan takes around +7secs or +2secs from cache.

![screenshot](http://localhost:8080/screenshot.png)
