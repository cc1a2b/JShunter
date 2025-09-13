package main

import (
    "bufio"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "io/ioutil"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
)


var (
    version = "v0.3"
    colors = map[string]string{
        "RED":    "\033[0;31m",
        "GREEN":  "\033[0;32m",
        "BLUE":   "\033[0;34m",
        "YELLOW": "\033[0;33m",
        "CYAN":   "\033[0;36m",
        "PURPLE": "\033[0;35m",
        "NC":     "\033[0m",
    }
)



var (
    //regex-cc1a2b
    regexPatterns = map[string]*regexp.Regexp{
	"Google API":                    regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"Firebase":                      regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}(?:\s|$|[^A-Za-z0-9_-])`),
	"Google Captcha":                regexp.MustCompile(`6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`),
	"Amazon Aws Access Key ID":      regexp.MustCompile(`A[SK]IA[0-9A-Z]{16}`),
	"Amazon Mws Auth Token":         regexp.MustCompile(`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"Amazon Aws Url":                regexp.MustCompile(`s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`),
	"Amazon Aws Url2":               regexp.MustCompile(`([a-zA-Z0-9-._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-._]+|s3-[a-zA-Z0-9-._/]+|s3.amazonaws.com/[a-zA-Z0-9-._]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-._]+)`),
	"Facebook Access Token":         regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
	"Authorization Basic":           regexp.MustCompile(`(?i)\bauthorization\s*:\s*basic\s+[a-zA-Z0-9=:_\+\/-]{20,100}`),
	"Authorization Bearer":          regexp.MustCompile(`(?i)\bauthorization\s*:\s*bearer\s+[a-zA-Z0-9_\-\.=:_\+\/]{20,100}`),
    "Authorization Api":             regexp.MustCompile(`(?i)\bapi[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9_\-]{20,100}["']?`),
	"Twilio Api Key":                regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	"Twilio Account Sid":            regexp.MustCompile(`(?i)\b(?:twilio|tw)\s*[_-]?account[_-]?sid\s*[:=]\s*["']?AC[a-zA-Z0-9_\-]{32}["']?`),
	"Twilio App Sid":                regexp.MustCompile(`AP[a-zA-Z0-9_\-]{32}`),
	"Paypal Braintre Access Token":  regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"Square Oauth Secret":           regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`),
	"Square Access Token":           regexp.MustCompile(`sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`),
	"Stripe Standard Api":           regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	"Stripe Restricted Api":         regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
	"Authorization Github Token":    regexp.MustCompile(`\bghp_[a-zA-Z0-9]{36}\b`),
	"Github Access Token":           regexp.MustCompile(`[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`),
	"Rsa Private Key":               regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	"Ssh Dsa Private Key":           regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
	"Ssh Dc Private Key":            regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	"Pgp Private Block":             regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	"Ssh Private Key":               regexp.MustCompile(`(?s)-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9+\/=\n]+-----END OPENSSH PRIVATE KEY-----`),
	"Json Web Token":                regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`),
    "Putty Private Key":             regexp.MustCompile(`(?s)PuTTY-User-Key-File-2.*?-----END`),
    "Ssh2 Encrypted Private Key":    regexp.MustCompile(`(?s)-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----[a-zA-Z0-9+\/=\n]+-----END SSH2 ENCRYPTED PRIVATE KEY-----`),
    "Generic Private Key":           regexp.MustCompile(`(?s)-----BEGIN.*PRIVATE KEY-----[a-zA-Z0-9+\/=\n]+-----END.*PRIVATE KEY-----`),
    "Username Password Combo":       regexp.MustCompile(`(?i)^[a-z]+:\/\/[^\/]*:[^@]+@`),
    "Facebook Oauth":                regexp.MustCompile(`(?i)[fF][aA][cC][eE][bB][oO][oO][kK].*['\"]?[0-9a-f]{32}['\"]?`),
    "Twitter Oauth":                 regexp.MustCompile(`(?i)\b(?:twitter|tw)\s*[_-]?oauth[_-]?token\s*[:=]\s*["']?[0-9a-zA-Z]{35,44}["']?`),
    "Github Token":                  regexp.MustCompile(`(?i)\b(gh[pousr]_[0-9a-zA-Z]{36})\b`),
    "Google Oauth Client Secret":    regexp.MustCompile(`\"client_secret\":\"[a-zA-Z0-9-_]{24}\"`),
    "Aws Api Key":                   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	"Slack Token":                   regexp.MustCompile(`\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"`),
	"Ssh Priv Key":                  regexp.MustCompile(`([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`),
	"Heroku Api Key":                regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"Slack Webhook Url":             regexp.MustCompile(`https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`),
	"Heroku Api Key 2":              regexp.MustCompile(`[hH]eroku[a-zA-Z0-9]{32}`),
	"Dropbox Access Token":          regexp.MustCompile(`(?i)^sl\.[A-Za-z0-9_-]{16,50}$`),
	"Salesforce Access Token":       regexp.MustCompile(`00D[0-9A-Za-z]{15,18}![A-Za-z0-9]{40}`),
	"Twitter Bearer Token":          regexp.MustCompile(`(?i)^AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9]{30,45}$`),
	"Firebase Url":                  regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`),
	"Pem Private Key":               regexp.MustCompile(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`),
	"Google Cloud Sa Key":           regexp.MustCompile(`"type": "service_account"`),
	"Stripe Publishable Key":        regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`),
	"Azure Storage Account Key":     regexp.MustCompile(`(?i)^[A-Za-z0-9]{44}=[A-Za-z0-9+/=]{0,43}$`),
	"Instagram Access Token":        regexp.MustCompile(`IGQV[A-Za-z0-9._-]{10,}`),
	"Stripe Test Publishable Key":   regexp.MustCompile(`pk_test_[0-9a-zA-Z]{24}`),
	"Stripe Test Secret Key":        regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24}`),
	"Slack Bot Token":               regexp.MustCompile(`xoxb-[A-Za-z0-9-]{24,34}`),
	"Slack User Token":              regexp.MustCompile(`xoxp-[A-Za-z0-9-]{24,34}`),
    "Google Gmail Api Key":          regexp.MustCompile(`AIza[0-9A-Za-z\\-_]{35}`),
    "Google Gmail Oauth":            regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`),
    "Google Oauth Access Token":     regexp.MustCompile(`ya29\.[0-9A-Za-z\\-_]+`),
    "Mailchimp Api Key":             regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`),
    "Mailgun Api Key":               regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
    "Google Drive Oauth":            regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`),
    "Paypal Braintree Access Token": regexp.MustCompile(`access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}`),
    "Picatic Api Key":               regexp.MustCompile(`sk_live_[0-9a-z]{32}`),
    "Stripe Api Key":                regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
    "Stripe Restricted Api Key":     regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
    "Square Access Token 2":         regexp.MustCompile(`sq0atp-[0-9A-Za-z\\-_]{22}`),
    "Square Oauth Secret 2":         regexp.MustCompile(`sq0csp-[0-9A-Za-z\\-_]{43}`),
    "Twitter Access Token":          regexp.MustCompile(`(?i)\b(?:twitter|tw)\s*[_-]?access[_-]?token\s*[:=]\s*["']?[0-9]+-[0-9a-zA-Z]{40}["']?`),
	"Heroku Api Key 3":              regexp.MustCompile(`(?i)[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`),
    "Generic Api Key":               regexp.MustCompile(`(?i)\bapi[_-]?key\s*[:=]\s*['\"]?[0-9a-zA-Z]{32,45}['\"]?`),
    "Generic Secret":                regexp.MustCompile(`(?i)\bsecret\s*[:=]\s*['\"]?[0-9a-zA-Z]{32,45}['\"]?`),
    "Slack Webhook":                 regexp.MustCompile(`https://hooks[.]slack[.]com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),
    "Gcp Service Account":           regexp.MustCompile(`\"type\": \"service_account\"`),
    "Password in Url":               regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]`),
	"Discord Webhook url":           regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_-]{64,}`),
	"Discord bot Token":             regexp.MustCompile(`[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`),
	"Okta Api Token":                regexp.MustCompile(`00[a-zA-Z0-9]{30}\.[a-zA-Z0-9\-_]{30,}\.[a-zA-Z0-9\-_]{30,}`),
	"Sendgrid Api Key":              regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
	"Mapbox Access Token":           regexp.MustCompile(`pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}`),
	"Gitlab Personal Access token":  regexp.MustCompile(`glpat-[A-Za-z0-9\-]{20}`),
	"Datadog Api Key":               regexp.MustCompile(`ddapi_[a-zA-Z0-9]{32}`),
	"shopify Access Token":          regexp.MustCompile(`shpat_[A-Za-z0-9]{32}`),
    "Atlassian Access Token":        regexp.MustCompile(`[a-zA-Z0-9]{20,}\.[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]{25,}`),
	"Crowdstrike Api Key":           regexp.MustCompile(`(?i)^[A-Za-z0-9]{32}\.[A-Za-z0-9]{16}$`),
	"Quickbooks Api Key":            regexp.MustCompile(`A[0-9a-f]{32}`),
	"Cisco Api Key":                 regexp.MustCompile(`cisco[A-Za-z0-9]{30}`),
	"Cisco Access Token":            regexp.MustCompile(`access_token=\w+`),
	"Segment Write Key":             regexp.MustCompile(`sk_[A-Za-z0-9]{32}`),
	"Tiktok Access Token":           regexp.MustCompile(`tiktok_access_token=[a-zA-Z0-9_]+`),
	"Slack Client Secret":           regexp.MustCompile(`xoxs-[0-9]{1,9}.[0-9A-Za-z]{1,12}.[0-9A-Za-z]{24,64}`),
    "Phone Number":                  regexp.MustCompile(`^\+\d{9,14}$`),
    "Email":                         regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	"Ali Cloud Access Key":		     regexp.MustCompile(`^LTAI[A-Za-z0-9]{12,20}$`),
	"Tencent Cloud Access Key":	     regexp.MustCompile(`^AKID[A-Za-z0-9]{13,20}$`),
    }

    asciiArt = `
         ________             __         
     __ / / __/ /  __ _____  / /____ ____
    / // /\ \/ _ \/ // / _ \/ __/ -_) __/
    \___/___/_//_/\_,_/_//_/\__/\__/_/  

     ` + version + `                         Created by cc1a2b
    `
)

func main() {
    var (
        url, list, jsFile, output, regex, cookies, proxy string
        threads                                           int
        quiet, help, update, extractEndpoints, skipTLS, foundOnly bool
    )


    flag.StringVar(&url, "u", "", "Input a URL")
    flag.StringVar(&url, "url", "", "Input a URL")
    flag.StringVar(&list, "l", "", "Input a file with URLs (.txt)")
    flag.StringVar(&list, "list", "", "Input a file with URLs (.txt)")
    flag.StringVar(&jsFile, "f", "", "Path to JavaScript file")
    flag.StringVar(&jsFile, "file", "", "Path to JavaScript file")
    flag.StringVar(&output, "o", "", "Output file path")
    flag.StringVar(&output, "output", "", "Output file path")
    flag.StringVar(&regex, "r", "", "RegEx for filtering results (endpoints and sensitive data)")
    flag.StringVar(&regex, "regex", "", "RegEx for filtering results (endpoints and sensitive data)")
    flag.StringVar(&cookies, "c", "", "Cookies for authenticated JS files")
    flag.StringVar(&cookies, "cookies", "", "Cookies for authenticated JS files")
    flag.StringVar(&proxy, "p", "", "Set proxy (host:port)")
    flag.StringVar(&proxy, "proxy", "", "Set proxy (host:port)")
    flag.IntVar(&threads, "t", 5, "Number of concurrent threads")
    flag.IntVar(&threads, "threads", 5, "Number of concurrent threads")
    flag.BoolVar(&quiet, "q", false, "Quiet mode: suppress ASCII art output")
    flag.BoolVar(&quiet, "quiet", false, "Quiet mode: suppress ASCII art output")
    flag.BoolVar(&help, "h", false, "Display help message")
    flag.BoolVar(&help, "help", false, "Display help message")
    flag.BoolVar(&update, "update", false, "Update the tool with latest patterns")
    flag.BoolVar(&update, "up", false, "Update the tool to latest version")
    flag.BoolVar(&extractEndpoints, "ep", false, "Extract endpoints from JavaScript files")
    flag.BoolVar(&extractEndpoints, "end-point", false, "Extract endpoints from JavaScript files")
    flag.BoolVar(&skipTLS, "k", false, "Skip TLS certificate verification")
    flag.BoolVar(&skipTLS, "skip-tls", false, "Skip TLS certificate verification")
    flag.BoolVar(&foundOnly, "fo", false, "Only show results when sensitive data is found (hide MISSING messages)")
    flag.BoolVar(&foundOnly, "found-only", false, "Only show results when sensitive data is found (hide MISSING messages)")


    flag.Parse()

    if help {
        customHelp()
        return
    }

    if update {
        updateTool()
        return
    }



    if url == "" && list == "" && jsFile == "" {
        if isInputFromStdin() {
            scanner := bufio.NewScanner(os.Stdin)
            for scanner.Scan() {
                inputURL := scanner.Text()
                
                if extractEndpoints {
                    processInputsForEndpoints(inputURL, list, output, regex, cookies, proxy, threads, skipTLS, foundOnly)
                } else {
                    processInputs(inputURL, list, output, regex, cookies, proxy, threads, skipTLS, foundOnly)
                }
            }
            if err := scanner.Err(); err != nil {
                fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
            }
            return
        }
        customHelp()
        os.Exit(1)
    }


    if !quiet {
        time.Sleep(100 * time.Millisecond)
        displayAsciiArt()
    }


    if quiet {
        disableColors()
    }


    if jsFile != "" {
        if extractEndpoints {
            processJSFileForEndpoints(jsFile, regex, output)
        } else {
            processJSFile(jsFile, regex)
        }
        return 
    }

    if extractEndpoints && (url != "" || list != "") {
        processInputsForEndpoints(url, list, output, regex, cookies, proxy, threads, skipTLS, foundOnly)
    } else {
        processInputs(url, list, output, regex, cookies, proxy, threads, skipTLS, foundOnly)
    }
}


func displayAsciiArt() {
    versionStatus := getVersionStatus()
    var statusColor string
    var statusText string
    
    switch versionStatus {
    case "latest":
        statusColor = colors["GREEN"]
        statusText = "latest"
    case "outdated":
        statusColor = colors["RED"]
        statusText = "outdated"
    default:
        statusColor = colors["YELLOW"]
        statusText = "Unknown"
    }
    
    fmt.Printf(`
         ________             __         
     __ / / __/ /  __ _____  / /____ ____
    / // /\ \/ _ \/ // / _ \/ __/ -_) __/
    \___/___/_//_/\_,_/_//_/\__/\__/_/  

     %s (%s%s%s%s)                         Created by cc1a2b
`, version, statusColor, statusText, colors["NC"], "")
}

func customHelp() {
    displayAsciiArt()
    fmt.Println("Usage:")
    fmt.Println("  -u, --url URL                 Input a URL")
    fmt.Println("  -l, --list FILE.txt           Input a file with URLs (.txt)")
    fmt.Println("  -f, --file FILE.js            Path to JavaScript file")
    fmt.Println()
    fmt.Println("Options:")
    fmt.Println("  -t, --threads INT             Number of concurrent threads (default: 5)")
    fmt.Println("  -c, --cookies <cookies>       Cookies for authenticated JS files")
    fmt.Println("  -p, --proxy host:port         Set proxy (host:port), e.g., 127.0.0.1:8080 for Burp Suite")
    fmt.Println("  -nc, --no-color               Disable color output")
    fmt.Println("  -q, --quiet                   Suppress ASCII art output")
    fmt.Println("  -o, --output FILENAME.txt     Output file path")
    fmt.Println("  -r, --regex <pattern>         RegEx for filtering results (endpoints and sensitive data)")
    fmt.Println("  --update, --up                Update the tool to latest version")
    fmt.Println("  -ep, --end-point              Extract endpoints from JavaScript files")
    fmt.Println("  -k, --skip-tls                Skip TLS certificate verification")
    fmt.Println("  -fo, --found-only             Only show results when sensitive data is found (hide MISSING messages)")
    fmt.Println("  -h, --help                    Display this help message")
}

func processStdin(output, regex, cookies, proxy string, threads int) {
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        fmt.Println("Processing line from stdin:", line)

    }
    if err := scanner.Err(); err != nil {
        fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
    }
}


func isInputFromStdin() bool {
    fi, err := os.Stdin.Stat()
    if err != nil {
        fmt.Println("Error checking stdin:", err)
        return false
    }
    return fi.Mode()&os.ModeCharDevice == 0 
}

func disableColors() {
    for k := range colors {
        colors[k] = ""
    }
}


func processJSFile(jsFile, regex string) {
    if _, err := os.Stat(jsFile); os.IsNotExist(err) {
        fmt.Printf("[%sERROR%s] File not found: %s\n", colors["RED"], colors["NC"], jsFile)
    } else if err != nil {
        fmt.Printf("[%sERROR%s] Unable to access file %s: %v\n", colors["RED"], colors["NC"], jsFile, err)
    } else {
        fmt.Printf("[%sFOUND%s] FILE: %s\n", colors["RED"], colors["NC"], jsFile)
        searchForSensitiveData(jsFile, regex, "", "", false, false)
    }
}


func processInputs(url, list, output, regex, cookie, proxy string, threads int, skipTLS, foundOnly bool) {
    var wg sync.WaitGroup
    urlChannel := make(chan string)

    var fileWriter *os.File
    if output != "" {
        var err error
        fileWriter, err = os.Create(output)
        if err != nil {
            fmt.Printf("Error creating output file: %v\n", err)
            return
        }
        defer fileWriter.Close()
    }

    for i := 0; i < threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for u := range urlChannel {
                _, sensitiveData := searchForSensitiveData(u, regex, cookie, proxy, skipTLS, foundOnly)

                if fileWriter != nil {
                    fmt.Fprintln(fileWriter, "URL:", u)
                    for name, matches := range sensitiveData {
                        for _, match := range matches {
                            fmt.Fprintf(fileWriter, "Sensitive Data [%s%s%s]: %s\n", colors["YELLOW"], name, colors["NC"], match)
                        }
                    }
                } else {
                    for name, matches := range sensitiveData {
                        for _, match := range matches {
                            fmt.Printf("Sensitive Data [%s%s%s]: %s\n", colors["YELLOW"], name, colors["NC"], match)
                        }
                    }
                }
            }
        }()
    }

    if err := enqueueURLs(url, list, urlChannel, regex); err != nil {
        fmt.Printf("Error in input processing: %v\n", err)
        close(urlChannel)
        return
    }

    close(urlChannel)
    wg.Wait()
}


func enqueueURLs(url, list string, urlChannel chan<- string, regex string) error {
    if list != "" {
        return enqueueFromFile(list, urlChannel)
    } else if url != "" {
        enqueueSingleURL(url, urlChannel, regex)
    } else {
        enqueueFromStdin(urlChannel)
    }
    return nil
}

func enqueueFromFile(filename string, urlChannel chan<- string) error {
    file, err := os.Open(filename)
    if err != nil {
        return fmt.Errorf("Error opening file: %w", err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        urlChannel <- scanner.Text()
    }
    return scanner.Err()
}

func enqueueSingleURL(url string, urlChannel chan<- string, regex string) {
    if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
        urlChannel <- url
    } else {
        processJSFile(url, regex)
    }
}

func enqueueFromStdin(urlChannel chan<- string) {
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        urlChannel <- scanner.Text()
    }
    if err := scanner.Err(); err != nil {
        fmt.Printf("Error reading from stdin: %v\n", err)
    }
}


func searchForSensitiveData(urlStr, regex, cookie, proxy string, skipTLS, foundOnly bool) (string, map[string][]string) {
    var client *http.Client

    transport := &http.Transport{}
    
    if skipTLS {
        transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    }
    
    if proxy != "" {
        proxyURL, err := url.Parse(proxy)
        if err != nil {
            fmt.Printf("Invalid proxy URL: %v\n", err)
            return urlStr, nil
        }
        transport.Proxy = http.ProxyURL(proxyURL)
    }
    
    client = &http.Client{Transport: transport}

    var sensitiveData map[string][]string

    if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
        req, err := http.NewRequest("GET", urlStr, nil)
        if err != nil {
            fmt.Printf("Failed to create request for URL %s: %v\n", urlStr, err)
            return urlStr, nil
        }

        if cookie != "" {
            req.Header.Set("Cookie", cookie)
        }

        resp, err := client.Do(req)
        if err != nil {
            return urlStr, nil
        }
        defer resp.Body.Close()

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            fmt.Printf("Error reading response body: %v\n", err)
            return urlStr, nil
        }

        sensitiveData = reportMatches(urlStr, body, regexPatterns, regex, foundOnly)
    } else {
        body, err := ioutil.ReadFile(urlStr)
        if err != nil {
            fmt.Printf("Error reading local file %s: %v\n", urlStr, err)
            return urlStr, nil
        }

        sensitiveData = reportMatches(urlStr, body, regexPatterns, regex, foundOnly)
    }

    return urlStr, sensitiveData
}


func isUnwantedEmail(email string) bool {
    unwantedPrefixes := []string{
        "info@", "career@", "jobs@", "admin@", "support@", "contact@", 
        "help@", "noreply@", "no-reply@", "test@", "demo@", "example@",
    }
    
    unwantedDomains := []string{
        "example.com", "test.com", "localhost", "example.org", "example.net",
    }
    
    email = strings.ToLower(email)
    
    // Check unwanted prefixes
    for _, prefix := range unwantedPrefixes {
        if strings.HasPrefix(email, prefix) {
            return true
        }
    }
    
    // Check unwanted domains
    for _, domain := range unwantedDomains {
        if strings.HasSuffix(email, "@"+domain) {
            return true
        }
    }
    
    return false
}

func reportMatches(source string, body []byte, regexPatterns map[string]*regexp.Regexp, filterRegex string, foundOnly bool) map[string][]string {
    matchesMap := make(map[string][]string)

    for name, pattern := range regexPatterns {
        if pattern.Match(body) {
            matches := pattern.FindAllString(string(body), -1)
            if len(matches) > 0 {
                // Apply regex filter if provided
                if filterRegex != "" {
                    filterPattern, err := regexp.Compile(filterRegex)
                    if err == nil {
                        filteredMatches := []string{}
                        for _, match := range matches {
                            if filterPattern.MatchString(match) {
                                filteredMatches = append(filteredMatches, match)
                            }
                        }
                        if len(filteredMatches) > 0 {
                            matchesMap[name] = append(matchesMap[name], filteredMatches...)
                        }
                    }
                } else {
                    // Special filtering for emails
                    if name == "Email" {
                        filteredMatches := []string{}
                        for _, match := range matches {
                            if !isUnwantedEmail(match) {
                                filteredMatches = append(filteredMatches, match)
                            }
                        }
                        if len(filteredMatches) > 0 {
                            matchesMap[name] = append(matchesMap[name], filteredMatches...)
                        }
                    } else {
                        matchesMap[name] = append(matchesMap[name], matches...)
                    }
                }
            }
        }
    }

    if len(matchesMap) > 0 {
        fmt.Printf("[%s FOUND %s] Sensitive data at: %s\n", colors["RED"], colors["NC"], source)
    } else {
        if !foundOnly {
            fmt.Printf("[%sMISSING%s] No sensitive data found at: %s\n", colors["BLUE"], colors["NC"], source)
        }
    }

    return matchesMap
}

func getVersionStatus() string {
    currentVersion := version
    
    resp, err := http.Get("https://api.github.com/repos/cc1a2b/jshunter/releases/latest")
    if err != nil {
        return "Unknown"
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return "Unknown"
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return "Unknown"
    }
    
    var release struct {
        TagName string `json:"tag_name"`
    }
    
    err = json.Unmarshal(body, &release)
    if err != nil {
        return "Unknown"
    }
    
    latestVersion := release.TagName
    
    if latestVersion == currentVersion {
        return "latest"
    }
    
    return "outdated"
}

func updateTool() {
    fmt.Printf("[%sINFO%s] Checking for updates...\n", colors["BLUE"], colors["NC"])
    
    currentVersion := version
    
    resp, err := http.Get("https://api.github.com/repos/cc1a2b/jshunter/releases/latest")
    if err != nil {
        fmt.Printf("[%sERROR%s] Failed to check for updates: %v\n", colors["RED"], colors["NC"], err)
        fmt.Printf("[%sINFO%s] You can manually update from: https://github.com/cc1a2b/jshunter/releases\n", colors["YELLOW"], colors["NC"])
        return
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        fmt.Printf("[%sERROR%s] Failed to fetch release information\n", colors["RED"], colors["NC"])
        fmt.Printf("[%sINFO%s] You can manually update from: https://github.com/cc1a2b/jshunter/releases\n", colors["YELLOW"], colors["NC"])
        return
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("[%sERROR%s] Failed to read response: %v\n", colors["RED"], colors["NC"], err)
        return
    }
    
    var release struct {
        TagName string `json:"tag_name"`
        Assets  []struct {
            Name               string `json:"name"`
            BrowserDownloadURL string `json:"browser_download_url"`
        } `json:"assets"`
    }
    
    err = json.Unmarshal(body, &release)
    if err != nil {
        fmt.Printf("[%sERROR%s] Failed to parse release information: %v\n", colors["RED"], colors["NC"], err)
        return
    }
    
    latestVersion := release.TagName
    
    if latestVersion == currentVersion {
        fmt.Printf("[%sINFO%s] You are already running the latest version: %s\n", colors["GREEN"], colors["NC"], currentVersion)
        return
    }
    
    fmt.Printf("[%sINFO%s] New version available: %s (current: %s)\n", colors["YELLOW"], colors["NC"], latestVersion, currentVersion)
    
    var downloadURL string
    var binaryName string
    
    
    goos := "linux"
    goarch := "amd64"
    
    binaryName = fmt.Sprintf("jshunter_%s_%s", goos, goarch)
    
    for _, asset := range release.Assets {
        if strings.Contains(asset.Name, goos) && strings.Contains(asset.Name, goarch) {
            downloadURL = asset.BrowserDownloadURL
            binaryName = asset.Name
            break
        }
    }
    
    if downloadURL == "" {
        fmt.Printf("[%sERROR%s] No suitable binary found for your platform\n", colors["RED"], colors["NC"])
        fmt.Printf("[%sINFO%s] Please download manually from: https://github.com/cc1a2b/jshunter/releases/tag/%s\n", colors["YELLOW"], colors["NC"], latestVersion)
        return
    }
    
    fmt.Printf("[%sINFO%s] Downloading %s...\n", colors["BLUE"], colors["NC"], binaryName)
    
    resp, err = http.Get(downloadURL)
    if err != nil {
        fmt.Printf("[%sERROR%s] Failed to download update: %v\n", colors["RED"], colors["NC"], err)
        return
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        fmt.Printf("[%sERROR%s] Failed to download update (status: %d)\n", colors["RED"], colors["NC"], resp.StatusCode)
        return
    }
    
    binaryData, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("[%sERROR%s] Failed to read binary data: %v\n", colors["RED"], colors["NC"], err)
        return
    }
    
    currentPath, err := os.Executable()
    if err != nil {
        fmt.Printf("[%sERROR%s] Failed to get current executable path: %v\n", colors["RED"], colors["NC"], err)
        return
    }
    
    backupPath := currentPath + ".backup"
    err = os.Rename(currentPath, backupPath)
    if err != nil {
        fmt.Printf("[%sERROR%s] Failed to create backup: %v\n", colors["RED"], colors["NC"], err)
        return
    }
    
    err = ioutil.WriteFile(currentPath, binaryData, 0755)
    if err != nil {
        fmt.Printf("[%sERROR%s] Failed to write new binary: %v\n", colors["RED"], colors["NC"], err)
        os.Rename(backupPath, currentPath)
        return
    }
    
    os.Remove(backupPath)
    
    fmt.Printf("[%sSUCCESS%s] Successfully updated to %s!\n", colors["GREEN"], colors["NC"], latestVersion)
    fmt.Printf("[%sINFO%s] Restart the tool to use the new version.\n", colors["BLUE"], colors["NC"])
}

func processJSFileForEndpoints(jsFile, regex, output string) {
    if _, err := os.Stat(jsFile); os.IsNotExist(err) {
        fmt.Printf("[%sERROR%s] File not found: %s\n", colors["RED"], colors["NC"], jsFile)
        return
    } else if err != nil {
        fmt.Printf("[%sERROR%s] Unable to access file %s: %v\n", colors["RED"], colors["NC"], jsFile, err)
        return
    }
    
    endpoints := extractEndpointsFromFile(jsFile, regex)
    
    if output != "" {
        writeEndpointsToFile(endpoints, output, jsFile)
    } else {
        displayEndpoints(endpoints, jsFile)
    }
}

func processInputsForEndpoints(url, list, output, regex, cookie, proxy string, threads int, skipTLS, foundOnly bool) {
    var wg sync.WaitGroup
    urlChannel := make(chan string)
    
    var fileWriter *os.File
    if output != "" {
        var err error
        fileWriter, err = os.Create(output)
        if err != nil {
            fmt.Printf("Error creating output file: %v\n", err)
            return
        }
        defer fileWriter.Close()
    }
    
    for i := 0; i < threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for u := range urlChannel {
                endpoints := extractEndpointsFromURL(u, regex, cookie, proxy, skipTLS)
                
                if fileWriter != nil {
                    fmt.Fprintf(fileWriter, "URL: %s\n", u)
                    for _, endpoint := range endpoints {
                        fmt.Fprintf(fileWriter, "ENDPOINT: %s\n", endpoint)
                    }
                    fmt.Fprintln(fileWriter, "")
                } else {
                    for _, endpoint := range endpoints {
                        fmt.Println(endpoint)
                    }
                }
            }
        }()
    }
    
    if err := enqueueURLs(url, list, urlChannel, regex); err != nil {
        fmt.Printf("Error in input processing: %v\n", err)
        close(urlChannel)
        return
    }
    
    close(urlChannel)
    wg.Wait()
}

func extractEndpointsFromFile(filePath, regex string) []string {
    body, err := ioutil.ReadFile(filePath)
    if err != nil {
        fmt.Printf("Error reading file %s: %v\n", filePath, err)
        return nil
    }
    
    return extractEndpointsFromContent(string(body), regex, "")
}

func extractEndpointsFromURL(urlStr, regex, cookie, proxy string, skipTLS bool) []string {
    var client *http.Client
    
    transport := &http.Transport{}
    
    if skipTLS {
        transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
    }
    
    if proxy != "" {
        proxyURL, err := url.Parse(proxy)
        if err != nil {
            return nil 
        }
        transport.Proxy = http.ProxyURL(proxyURL)
    }
    
    client = &http.Client{Transport: transport}
    
    req, err := http.NewRequest("GET", urlStr, nil)
    if err != nil {
        return nil 
    }
    
    if cookie != "" {
        req.Header.Set("Cookie", cookie)
    }
    
    resp, err := client.Do(req)
    if err != nil {
        return nil 
    }
    defer resp.Body.Close()
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil 
    }
    
    parsedURL, err := url.Parse(urlStr)
    if err != nil {
        return nil
    }
    baseURL := parsedURL.Scheme + "://" + parsedURL.Host
    
    return extractEndpointsFromContent(string(body), regex, baseURL)
}

func extractEndpointsFromContent(content, regex, targetDomain string) []string {
    var endpoints []string
    var baseURLs []string

    baseURLPatterns := map[string]*regexp.Regexp{
        "base_url":        regexp.MustCompile(`baseURL\s*[:=]\s*["']([^"']*)["']`),
        "api_base":        regexp.MustCompile(`apiBase\s*[:=]\s*["']([^"']*)["']`),
        "api_url":         regexp.MustCompile(`API_URL\s*[:=]\s*["']([^"']*)["']`),
        "server_url":      regexp.MustCompile(`SERVER_URL\s*[:=]\s*["']([^"']*)["']`),
        "endpoint_base":   regexp.MustCompile(`endpointBase\s*[:=]\s*["']([^"']*)["']`),
    }
    
    for _, pattern := range baseURLPatterns {
        matches := pattern.FindAllStringSubmatch(content, -1)
        for _, match := range matches {
            if len(match) > 1 {
                baseURL := strings.Trim(match[1], `"'`)
                if baseURL != "" && !contains(baseURLs, baseURL) {
                    baseURLs = append(baseURLs, baseURL)
                }
            }
        }
    }
    
    endpointPatterns := map[string]*regexp.Regexp{
        "ajax_url":        regexp.MustCompile(`\.ajax\s*\(\s*["']([^"']*)["']`),
        "fetch_url":       regexp.MustCompile(`fetch\s*\(\s*["']([^"']*)["']`),
        "xhr_url":         regexp.MustCompile(`\.open\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']*)["']`),
        "axios_url":       regexp.MustCompile(`axios\.[a-z]+\s*\(\s*["']([^"']*)["']`),
        "request_url":     regexp.MustCompile(`request\.[a-z]+\s*\(\s*["']([^"']*)["']`),
        "api_endpoint":    regexp.MustCompile(`["'](/api/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%\-]*)["']`),
        "rest_endpoint":   regexp.MustCompile(`["'](/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%\-]*)["']`),
        "graphql_endpoint": regexp.MustCompile(`["'](/graphql[^"']*)["']`),
    }
    
    var relativeEndpoints []string
    for _, pattern := range endpointPatterns {
        matches := pattern.FindAllStringSubmatch(content, -1)
        for _, match := range matches {
            if len(match) > 1 {
                endpoint := strings.Trim(match[1], `"'`)
                if endpoint != "" && !contains(relativeEndpoints, endpoint) {
                    endpoint = cleanEndpoint(endpoint)
                    if isValidEndpoint(endpoint) {
                        relativeEndpoints = append(relativeEndpoints, endpoint)
                    }
                }
            }
        }
    }
    
    fullURLPatterns := map[string]*regexp.Regexp{
        "full_url":        regexp.MustCompile(`https?://[a-zA-Z0-9.-]+/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%\-]+`),
        "websocket_url":   regexp.MustCompile(`wss?://[a-zA-Z0-9.-]+/[a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%\-]+`),
    }
    
    for _, pattern := range fullURLPatterns {
        matches := pattern.FindAllString(content, -1)
        for _, match := range matches {
            match = cleanEndpoint(match)
            if match != "" && !contains(endpoints, match) && isValidEndpoint(match) {
                endpoints = append(endpoints, match)
            }
        }
    }
    
    for _, baseURL := range baseURLs {
        baseURL = strings.TrimRight(baseURL, "/")
        for _, relEndpoint := range relativeEndpoints {
            if strings.HasPrefix(relEndpoint, "/") {
                fullEndpoint := baseURL + relEndpoint
                if !contains(endpoints, fullEndpoint) {
                    endpoints = append(endpoints, fullEndpoint)
                }
            }
        }
    }
    
    if targetDomain != "" {
        if !strings.HasPrefix(targetDomain, "http") {
            targetDomain = "https://" + targetDomain
        }
        targetDomain = strings.TrimRight(targetDomain, "/")
        
        for _, relEndpoint := range relativeEndpoints {
            fullEndpoint := targetDomain + relEndpoint
            if !contains(endpoints, fullEndpoint) {
                endpoints = append(endpoints, fullEndpoint)
            }
        }
    } else {
        if len(baseURLs) > 0 {
            baseURL := strings.TrimRight(baseURLs[0], "/")
            for _, relEndpoint := range relativeEndpoints {
                fullEndpoint := baseURL + relEndpoint
                if !contains(endpoints, fullEndpoint) {
                    endpoints = append(endpoints, fullEndpoint)
                }
            }
        } else {
            for _, relEndpoint := range relativeEndpoints {
                if !contains(endpoints, relEndpoint) {
                    endpoints = append(endpoints, relEndpoint)
                }
            }
        }
    }
    
    if regex != "" {
        filteredEndpoints := []string{}
        customPattern, err := regexp.Compile(regex)
        if err != nil {
            fmt.Printf("Invalid regex pattern: %v\n", err)
            return endpoints
        }
        
        for _, endpoint := range endpoints {
            if customPattern.MatchString(endpoint) {
                filteredEndpoints = append(filteredEndpoints, endpoint)
            }
        }
        endpoints = filteredEndpoints
    }
    
    return endpoints
}


func cleanEndpoint(endpoint string) string {

    endpoint = strings.Trim(endpoint, `"'`)
    endpoint = strings.TrimSpace(endpoint)
    
    endpoint = strings.TrimRight(endpoint, ";,)")
    endpoint = strings.TrimRight(endpoint, `"'`)
    

    if strings.Contains(endpoint, "${") {
        return ""
    }
    

    endpoint = strings.Trim(endpoint, `"'`)
    

    endpoint = strings.TrimRight(endpoint, ";,)")
    endpoint = strings.TrimRight(endpoint, `"'`)
    
    return endpoint
}


func isValidEndpoint(endpoint string) bool {
   
    if endpoint == "" {
        return false
    }
    
    
    if strings.Contains(endpoint, "${") || strings.Contains(endpoint, "+") {
        return false
    }
    
   
    if len(endpoint) < 2 {
        return false
    }
    
    
    skipWords := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "true", "false", "null", "undefined"}
    for _, word := range skipWords {
        if endpoint == word {
            return false
        }
    }
    
  
    if strings.HasSuffix(endpoint, "'") || strings.HasSuffix(endpoint, "\"") || 
       strings.HasSuffix(endpoint, ";") || strings.HasSuffix(endpoint, ")") ||
       strings.HasSuffix(endpoint, "';") || strings.HasSuffix(endpoint, "\";") ||
       strings.HasSuffix(endpoint, "')") || strings.HasSuffix(endpoint, "\")") {
        return false
    }
    
    
    if strings.Contains(endpoint, "';") || strings.Contains(endpoint, "\";") ||
       strings.Contains(endpoint, "')") || strings.Contains(endpoint, "\")") {
        return false
    }
    

    if strings.Contains(endpoint, ",") || strings.Contains(endpoint, "(") || 
       strings.Contains(endpoint, "Y=") || strings.Contains(endpoint, "&") {
        return false
    }
    

    if strings.HasSuffix(endpoint, "/a") || strings.HasSuffix(endpoint, "/g") ||
       strings.HasSuffix(endpoint, "//") || strings.HasSuffix(endpoint, "/") {
        return false
    }
    

    if !strings.HasPrefix(endpoint, "/") && !strings.HasPrefix(endpoint, "http") {
        return false
    }
    

    externalDomains := []string{
        "fonts.googleapis.com",
        "fonts.gstatic.com", 
        "www.googletagmanager.com",
        "www.google-analytics.com",
        "static.hotjar.com",
        "www.hotjar.com",
        "cdnjs.cloudflare.com",
        "unpkg.com",
        "cdn.jsdelivr.net",
        "ajax.googleapis.com",
        "code.jquery.com",
        "maxcdn.bootstrapcdn.com",
        "stackpath.bootstrapcdn.com",
        "www.opensource.org",
        "flowplayer.org",
        "docs.jquery.com",
        "www.adobe.com",
        "www.w3.org",
        "jquery.com",
        "github.com",
        "raw.githubusercontent.com",
    }
    
    for _, domain := range externalDomains {
        if strings.Contains(endpoint, domain) {
            return false
        }
    }
    
   
    if strings.HasPrefix(endpoint, "http") {

        parts := strings.Split(endpoint, "/")
        if len(parts) < 4 || parts[3] == "" {
            return false
        }
        

        if strings.Contains(endpoint, "?family=") || strings.Contains(endpoint, "?id=") ||
           strings.Contains(endpoint, "&display=") || strings.Contains(endpoint, "&version=") {
            return false
        }
    }
    
    return true
}


func displayEndpoints(endpoints []string, source string) {
    if len(endpoints) > 0 {
        for _, endpoint := range endpoints {
            fmt.Println(endpoint)
        }
    }
}


func writeEndpointsToFile(endpoints []string, outputFile, source string) {
    file, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        fmt.Printf("Error opening output file: %v\n", err)
        return
    }
    defer file.Close()
    
    fmt.Fprintf(file, "SOURCE: %s\n", source)
    for _, endpoint := range endpoints {
        fmt.Fprintf(file, "ENDPOINT: %s\n", endpoint)
    }
    fmt.Fprintln(file, "")
    
    fmt.Printf("[%sSUCCESS%s] Endpoints saved to: %s\n", colors["GREEN"], colors["NC"], outputFile)
}


func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
