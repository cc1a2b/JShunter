package main

import (
    "bufio"
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


var colors = map[string]string{
    "RED":    "\033[0;31m",
    "GREEN":  "\033[0;32m",
    "BLUE":   "\033[0;34m",
    "YELLOW": "\033[0;33m",
    "CYAN":   "\033[0;36m",
    "PURPLE": "\033[0;35m",
    "NC":     "\033[0m", // No Color
}


// Define the default regex patterns
var (
    // Default regex patterns
    regexPatterns = map[string]*regexp.Regexp{
	"google_api":                    regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"firebase":                      regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`),
	"google_captcha":                regexp.MustCompile(`6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$`),
	"google_oauth":                  regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`),
	"amazon_aws_access_key_id":      regexp.MustCompile(`A[SK]IA[0-9A-Z]{16}`),
	"amazon_mws_auth_token":         regexp.MustCompile(`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"amazon_aws_url":                regexp.MustCompile(`s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`),
	"amazon_aws_url2":               regexp.MustCompile(`([a-zA-Z0-9-._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-._]+|s3-[a-zA-Z0-9-._/]+|s3.amazonaws.com/[a-zA-Z0-9-._]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-._]+)`),
	"facebook_access_token":         regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
	"authorization_basic":           regexp.MustCompile(`basic [a-zA-Z0-9=:_\+\/-]{5,100}`),
	"authorization_bearer":          regexp.MustCompile(`bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}`),
	"authorization_api":             regexp.MustCompile(`api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`),
	"mailgun_api_key":               regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
	"twilio_api_key":                regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	"twilio_account_sid":            regexp.MustCompile(`AC[a-zA-Z0-9_\-]{32}`),
	"twilio_app_sid":                regexp.MustCompile(`AP[a-zA-Z0-9_\-]{32}`),
	"paypal_braintree_access_token": regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"square_oauth_secret":           regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`),
	"square_access_token":           regexp.MustCompile(`sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}`),
	"stripe_standard_api":           regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	"stripe_restricted_api":         regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`),
	"github_access_token":           regexp.MustCompile(`[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*`),
	"rsa_private_key":               regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
	"ssh_dsa_private_key":           regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`),
	"ssh_dc_private_key":            regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
	"pgp_private_block":             regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
	"json_web_token":                regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$`),
	"slack_token":                   regexp.MustCompile(`\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"`),
	"SSH_privKey":                   regexp.MustCompile(`([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`),
	"Heroku API KEY":                regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	"slack_webhook_url":             regexp.MustCompile(`https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`),
	"heroku_api_key":                regexp.MustCompile(`[hH]eroku[a-zA-Z0-9]{32}`),
	"dropbox_access_token":          regexp.MustCompile(`sl\.[A-Za-z0-9_-]+`),
	"salesforce_access_token":       regexp.MustCompile(`00D[0-9A-Za-z]{15,18}![A-Za-z0-9]{40}`),
	"twitter_bearer_token":          regexp.MustCompile(`AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{30,45}`),
	"firebase_url":                  regexp.MustCompile(`https://[a-z0-9-]+\.firebaseio\.com`),
	"pem_private_key":               regexp.MustCompile(`-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----`),
	"google_cloud_sa_key":           regexp.MustCompile(`"type": "service_account"`),
	"stripe_publishable_key":        regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24}`),
	"azure_storage_account_key":     regexp.MustCompile(`[A-Za-z0-9+/=]{88}`),
	"instagram_access_token":        regexp.MustCompile(`IGQV[A-Za-z0-9._-]{10,}`),
	"stripe_test_publishable_key":   regexp.MustCompile(`pk_test_[0-9a-zA-Z]{24}`),
	"stripe_test_secret_key":        regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24}`),
	"slack_bot_token":               regexp.MustCompile(`xoxb-[A-Za-z0-9-]{24,34}`),
	"slack_user_token":              regexp.MustCompile(`xoxp-[A-Za-z0-9-]{24,34}`),
	"slack_webhook":                 regexp.MustCompile(`https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
	"discord_webhook_url":           regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]{18,20}/[A-Za-z0-9_-]{64,}`),
	"discord_bot_token":             regexp.MustCompile(`[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`),
	"okta_api_token":                regexp.MustCompile(`00[a-zA-Z0-9]{30}\.[a-zA-Z0-9\-_]{30,}\.[a-zA-Z0-9\-_]{30,}`),
	"sendgrid_api_key":              regexp.MustCompile(`SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`),
	"mapbox_access_token":           regexp.MustCompile(`pk\.[a-zA-Z0-9]{60}\.[a-zA-Z0-9]{22}`),
	"gitlab_personal_access_token":  regexp.MustCompile(`glpat-[A-Za-z0-9\-]{20}`),
	"datadog_api_key":               regexp.MustCompile(`ddapi_[a-zA-Z0-9]{32}`),
	"shopify_access_token":          regexp.MustCompile(`shpat_[A-Za-z0-9]{32}`),
	"atlassian_access_token":        regexp.MustCompile(`[0-9a-z]{3}\.[0-9a-z]{1}\.[0-9a-z]{3}`),
	"crowdstrike_api_key":           regexp.MustCompile(`[\w-]{32}\.[\w-]{16}`),
	"quickbooks_api_key":            regexp.MustCompile(`A[0-9a-f]{32}`),
	"cisco_api_key":                 regexp.MustCompile(`cisco[A-Za-z0-9]{30}`),
	"cisco_access_token":            regexp.MustCompile(`access_token=\w+`),
	"segment_write_key":             regexp.MustCompile(`sk_[A-Za-z0-9]{32}`),
	"tiktok_access_token":           regexp.MustCompile(`tiktok_access_token=[a-zA-Z0-9_]+`),
	"slack_client_secret":           regexp.MustCompile(`xoxs-[0-9]{1,9}.[0-9A-Za-z]{1,12}.[0-9A-Za-z]{24,64}`),
        "phone_number":                  regexp.MustCompile(`^\+\d{9,14}$`),
        "email":                         regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
    }

    asciiArt = `
         ________             __         
     __ / / __/ /  __ _____  / /____ ____
    / // /\ \/ _ \/ // / _ \/ __/ -_) __/
    \___/___/_//_/\_,_/_//_/\__/\__/_/  

     v0.1                         Created by cc1a2b
    `
)

func main() {
    // Define command-line flags
    var url, list, jsFile, output, regex, cookies, proxy string
    var threads int
    var quiet, help bool

    // Define flags using StringVar and IntVar for both short and long options
    flag.StringVar(&url, "u", "", "Input a URL")
    flag.StringVar(&url, "url", "", "Input a URL") // Long option for URL
    flag.StringVar(&list, "l", "", "Input a file with URLs (.txt)")
    flag.StringVar(&list, "list", "", "Input a file with URLs (.txt)") // Long option for list
    flag.StringVar(&jsFile, "f", "", "Path to JavaScript file")
    flag.StringVar(&jsFile, "file", "", "Path to JavaScript file") // Long option for file
    flag.StringVar(&output, "o", "output.txt", "Where to save the output file (default: output.txt)")
    flag.StringVar(&output, "output", "output.txt", "Where to save the output file (default: output.txt)") // Long option for output
    flag.StringVar(&regex, "r", "", "RegEx for filtering purposes against found endpoints")
    flag.StringVar(&regex, "regex", "", "RegEx for filtering purposes against found endpoints") // Long option for regex
    flag.StringVar(&cookies, "c", "", "Add cookies for authenticated JS files")
    flag.StringVar(&cookies, "cookies", "", "Add cookies for authenticated JS files") // Long option for cookies
    flag.StringVar(&proxy, "p", "", "Set proxy (host:port)")
    flag.StringVar(&proxy, "proxy", "", "Set proxy (host:port)") // Long option for proxy
    flag.IntVar(&threads, "t", 5, "Number of concurrent threads")
    flag.IntVar(&threads, "threads", 5, "Number of concurrent threads") // Long option for threads
    flag.BoolVar(&quiet, "q", false, "Quiet mode: suppress ASCII art output")
    flag.BoolVar(&quiet, "quiet", false, "Quiet mode: suppress ASCII art output") // Long option for quiet
    flag.BoolVar(&help, "h", false, "Show help message")
    flag.BoolVar(&help, "help", false, "Show help message") // Long option for help

    // Parse the flags
    flag.Parse()

    // Show custom help if -h flag is used
    if help {
        customHelp()
        return
    }

    // Custom help output for no arguments or quiet mode
    if len(os.Args) == 1 || quiet {
        time.Sleep(100 * time.Millisecond) // Delay for 0.1 second
        customHelp()
        return
    }

    // Validate inputs
    if url == "" && list == "" && jsFile == "" {
        if isInputFromStdin() {
            processInputs("", "", output, regex, cookies, proxy, threads)
            return
        }
        fmt.Println("Error: Either -u, -l, or -f must be provided.")
        os.Exit(1)
    }

    // Handle quiet mode
    if !quiet {
        time.Sleep(100 * time.Millisecond) // Delay for 0.1 second
        fmt.Println(asciiArt)
    }

    // Set color variables based on `-nc` flag
    if quiet {
        disableColors()
    }

    // Process the JavaScript file if provided
    if jsFile != "" {
        processJSFile(jsFile, regex)
    }

    // Proceed with the main functionality
    processInputs(url, list, output, regex, cookies, proxy, threads)
}

// Custom help function to format usage output
func customHelp() {
    fmt.Println(asciiArt)
    fmt.Println("Usage:")
    fmt.Println("  -u, --url URL              Input a URL")
    fmt.Println("  -l, --list FILE.txt            Input a file with URLs (.txt)")
    fmt.Println("  -f, --file FILE.js            Path to JavaScript file")
    fmt.Println()
    fmt.Println("Options:")
    fmt.Println("  -t, --threads INT       Number of concurrent threads (default: 5)")
    fmt.Println("  -c, --cookies <cookies>      Add cookies for authenticated JS files")
    fmt.Println("  -p, --proxy host:port        Set proxy (host:port) , Burp 127.0.0.1:8080")
    fmt.Println("  -nc, --no-color              Disable color output")
    fmt.Println("  -q, --quiet                  Suppress ASCII art output")
    fmt.Println("  -o, --output FILENAME.txt          Where to save the output file (default: output.txt)")
    fmt.Println("  -r, --regex <pattern>        RegEx for filtering purposes against found endpoints")
    fmt.Println("  -h, --help                   Display this help message")
}

// Helper function to check if there is input from stdin
func isInputFromStdin() bool {
    fi, err := os.Stdin.Stat()
    return err == nil && fi.Mode()&os.ModeNamedPipe != 0
}

// Disables all color output by setting color codes to an empty string
func disableColors() {
    for k := range colors {
        colors[k] = ""
    }
}

// Processes a JS file and searches for sensitive data
func processJSFile(jsFile string, regex string) {
    if _, err := os.Stat(jsFile); os.IsNotExist(err) {
        fmt.Printf("[%sERROR%s] File not found: %s\n", colors["RED"], colors["NC"], jsFile)
        return
    } else if err != nil {
        fmt.Printf("[%sERROR%s] Unable to access file %s: %v\n", colors["RED"], colors["NC"], jsFile, err)
        return
    }

    fmt.Printf("[%sFOUND%s] FILE: %s\n", colors["RED"], colors["NC"], jsFile)
    searchForSensitiveData(jsFile, regex, "", "")
}

func processInputs(url, list, output, regex, cookie, proxy string, threads int) {
    var wg sync.WaitGroup
    urlChannel := make(chan string)

    // Prepare output file writer if specified
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

    // Start worker pool for concurrent processing
    for i := 0; i < threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for u := range urlChannel {
                _, sensitiveData := searchForSensitiveData(u, regex, cookie, proxy)

                if fileWriter != nil {
                    // Log processed URL and sensitive data to file
                    fmt.Fprintln(fileWriter, "URL:", u)
                    for name, matches := range sensitiveData {
                        for _, match := range matches {
                            fmt.Fprintf(fileWriter, "Sensitive Data [%s]: %s\n", name, match)
                        }
                    }
                } else {
                    // Print processed URL and sensitive data to console
                    fmt.Println("URL:", u)
                    for name, matches := range sensitiveData {
                        for _, match := range matches {
                            fmt.Printf("Sensitive Data [%s]: %s\n", name, match)
                        }
                    }
                }
            }
        }()
    }

    // Queue URLs or files for processing based on input type
    if err := enqueueURLs(url, list, urlChannel, regex); err != nil {
        fmt.Printf("Error in input processing: %v\n", err)
        close(urlChannel)
        return
    }

    // Close channel after enqueue and wait for all workers to finish
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
        processJSFile(url, regex) // Use your processJSFile function if URL is not a web link
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



func searchForSensitiveData(urlStr, regex, cookie, proxy string) (string, map[string][]string) {
    var client *http.Client

    // Configure the HTTP client with proxy if provided
    if proxy != "" {
        proxyURL, err := url.Parse(proxy)
        if err != nil {
            fmt.Printf("Invalid proxy URL: %v\n", err)
            return urlStr, nil
        }
        client = &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
    } else {
        client = &http.Client{}
    }

    var sensitiveData map[string][]string // This will store the sensitive data found

    // Check if the URL is HTTP/HTTPS
    if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
        req, err := http.NewRequest("GET", urlStr, nil)
        if err != nil {
            fmt.Printf("Failed to create request for URL %s: %v\n", urlStr, err)
            return urlStr, nil
        }

        // Add cookie to the request if provided
        if cookie != "" {
            req.Header.Set("Cookie", cookie)
        }

        // Send the HTTP request
        resp, err := client.Do(req)
        if err != nil {
            fmt.Printf("Failed to fetch URL %s: %v\n", urlStr, err)
            return urlStr, nil
        }
        defer resp.Body.Close()

        // Read the response body
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            fmt.Printf("Error reading response body: %v\n", err)
            return urlStr, nil
        }

        // Search for sensitive data using regex and store results
        sensitiveData = reportMatches(urlStr, body, regexPatterns)

    } else {
        // Attempt to read a local file
        body, err := ioutil.ReadFile(urlStr)
        if err != nil {
            fmt.Printf("Error reading local file %s: %v\n", urlStr, err)
            return urlStr, nil
        }

        // Search for sensitive data using regex and store results
        sensitiveData = reportMatches(urlStr, body, regexPatterns)
    }

    return urlStr, sensitiveData // Return the URL and the collected sensitive data
}

func reportMatches(source string, body []byte, regexPatterns map[string]*regexp.Regexp) map[string][]string {
    // Create a map to collect matches for each regex pattern
    matchesMap := make(map[string][]string)

    // Search for sensitive data using regex patterns
    for name, pattern := range regexPatterns {
        if pattern.Match(body) {
            // Extract all matches from the body using the regex
            matches := pattern.FindAllString(string(body), -1)
            if len(matches) > 0 {
                // Store matches in the map
                matchesMap[name] = append(matchesMap[name], matches...)
            }
        }
    }

    // Print all matches for each regex found
    if len(matchesMap) > 0 {
        fmt.Printf("[%sFOUND%s] Sensitive data at: %s\n", colors["RED"], colors["NC"], source)
        for name, matches := range matchesMap {
            for _, match := range matches {
                fmt.Printf("%s ==>> %s\n", name, match)
            }
        }
    } else {
        fmt.Printf("[%sMISSING%s] No sensitive data found at: %s\n", colors["BLUE"], colors["NC"], source)
    }

    return matchesMap // Return the collected matches
}
