package main

import (
    "bufio"
    "crypto/tls"
    "encoding/csv"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "io/ioutil"
    "math"
    "net"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "runtime"
    "sort"
    "strings"
    "sync"
    "time"
    "math/rand"
)


var (
    version = "v0.4"
    colors = map[string]string{
        "RED":    "\033[0;31m",
        "GREEN":  "\033[0;32m",
        "BLUE":   "\033[0;34m",
        "YELLOW": "\033[0;33m",
        "CYAN":   "\033[0;36m",
        "PURPLE": "\033[0;35m",
        "NC":     "\033[0m",
    }
    // Global deduplication for all outputs
    globalSeenParams = make(map[string]bool)
    globalSeenAll    = make(map[string]bool)
    globalSeenMutex  sync.Mutex
    globalFoundAny   = false // Track if any findings were made across all files
    missingMessages  = make([]string, 0) // Buffer for MISSING messages
    missingMutex     sync.Mutex
)



var (
    //regex-cc1a2b
    regexPatterns = map[string]*regexp.Regexp{
	"Google API":                    regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"Firebase":                      regexp.MustCompile(`AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}(?:\s|$|[^A-Za-z0-9_-])`),
	"Amazon Aws Access Key ID":      regexp.MustCompile(`A[SK]IA[0-9A-Z]{16}`),
	"Amazon Mws Auth Token":         regexp.MustCompile(`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`),
	"Amazon Aws Url":                regexp.MustCompile(`s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com`),
	"Amazon Aws Url2":               regexp.MustCompile(`([a-zA-Z0-9-._]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-._]+|s3-[a-z]{2}-[a-z]+-[0-9]+\.amazonaws\.com|s3.amazonaws.com/[a-zA-Z0-9-._]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-._]+)`),
	"Facebook Access Token":         regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`),
	"Authorization Basic":           regexp.MustCompile(`(?i)\bauthorization\s*:\s*basic\s+[a-zA-Z0-9=:_\+\/-]{20,100}`),
	"Authorization Bearer":          regexp.MustCompile(`(?i)\bauthorization\s*:\s*bearer\s+[a-zA-Z0-9_\-\.=:_\+\/]{20,100}`),
    "Authorization Api":             regexp.MustCompile(`(?i)\bapi[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9_\-]{20,100}["']?`),
	"Twilio Api Key":                regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
	"Twilio Account Sid":            regexp.MustCompile(`(?i)\b(?:twilio|tw)\s*[_-]?account[_-]?sid\s*[:=]\s*["']?AC[a-zA-Z0-9_\-]{32}["']?`),
	"Twilio App Sid":                regexp.MustCompile(`AP[a-zA-Z0-9_\-]{32}`),
	"Paypal Braintre Access Token":  regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`),
	"Square Oauth Secret":           regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}`),
	"Square Access Token":           regexp.MustCompile(`sqOatp-[0-9A-Za-z\-_]{22}`),
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
    "Facebook Oauth":                regexp.MustCompile(`(?i)(?:facebook|fb)[_\-]?(?:app[_\-]?)?(?:secret|client[_\-]?secret|oauth)\s*[:=]\s*['\"]?[0-9a-f]{32}['\"]?`),
    "Twitter Oauth":                 regexp.MustCompile(`(?i)\b(?:twitter|tw)\s*[_-]?oauth[_-]?token\s*[:=]\s*["']?[0-9a-zA-Z]{35,44}["']?`),
    "Github Token":                  regexp.MustCompile(`(?i)\b(gh[pousr]_[0-9a-zA-Z]{36})\b`),
    "Google Oauth Client Secret":    regexp.MustCompile(`\"client_secret\":\"[a-zA-Z0-9-_]{24}\"`),
    "Aws Api Key":                   regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	"Slack Token":                   regexp.MustCompile(`\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"`),
	"Ssh Priv Key":                  regexp.MustCompile(`([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)`),
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
        "OpenAI API Key":                regexp.MustCompile(`sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}`),
        "OpenAI API Key Project":        regexp.MustCompile(`sk-proj-[a-zA-Z0-9]{48,}`),
        "OpenAI API Key Svc":            regexp.MustCompile(`sk-svcacct-[a-zA-Z0-9_-]{80,}`),
        "Anthropic API Key":             regexp.MustCompile(`sk-ant-api[a-zA-Z0-9-]{37,}`),
        "HuggingFace Token":             regexp.MustCompile(`hf_[a-zA-Z0-9]{34,}`),
        "Cohere API Key":                regexp.MustCompile(`(?i)cohere[_-]?api[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9]{40}["']?`),
        "Replicate API Token":           regexp.MustCompile(`r8_[a-zA-Z0-9]{40}`),
        "Google AI API Key":             regexp.MustCompile(`(?i)(?:gemini|palm|bard)[_-]?api[_-]?key\s*[:=]\s*["']?AIza[a-zA-Z0-9_-]{35}["']?`),
        "AWS Secret Access Key":         regexp.MustCompile(`(?i)(?:aws)?[_-]?secret[_-]?(?:access)?[_-]?key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?`),
        "AWS Session Token":             regexp.MustCompile(`(?i)aws[_-]?session[_-]?token\s*[:=]\s*["']?[A-Za-z0-9/+=]{100,}["']?`),
        "MongoDB Connection String":     regexp.MustCompile(`mongodb(?:\+srv)?://[a-zA-Z0-9._-]+:[^@\s"']+@[a-zA-Z0-9._-]+`),
        "PostgreSQL Connection String":  regexp.MustCompile(`postgres(?:ql)?://[a-zA-Z0-9._-]+:[^@\s"']+@[a-zA-Z0-9._-]+`),
        "MySQL Connection String":       regexp.MustCompile(`mysql://[a-zA-Z0-9._-]+:[^@\s"']+@[a-zA-Z0-9._-]+`),
        "Redis Connection String":       regexp.MustCompile(`redis://[a-zA-Z0-9._-]+:[^@\s"']+@[a-zA-Z0-9._-]+`),
        "MSSQL Connection String":       regexp.MustCompile(`(?i)(?:server|data source)=[^;]+;.*(?:password|pwd)=[^;]+`),
        "Database URL Generic":          regexp.MustCompile(`(?i)(?:database|db)[_-]?url\s*[:=]\s*["']?[a-z]+://[^:]+:[^@]+@[^\s"']+["']?`),
        "Azure Client Secret":           regexp.MustCompile(`(?i)(?:azure|ad)[_-]?(?:client)?[_-]?secret\s*[:=]\s*["']?[a-zA-Z0-9~._-]{34,}["']?`),
        "Azure Storage Connection":      regexp.MustCompile(`DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{86,}`),
        "Azure SAS Token":               regexp.MustCompile(`(?i)[?&]sig=[a-zA-Z0-9%]{43,}`),
        "Azure SQL Connection":          regexp.MustCompile(`(?i)Server=tcp:[^;]+;.*Password=[^;]+`),
        "DigitalOcean Token":            regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
        "DigitalOcean OAuth":            regexp.MustCompile(`doo_v1_[a-f0-9]{64}`),
        "DigitalOcean Refresh":          regexp.MustCompile(`dor_v1_[a-f0-9]{64}`),
        "Linode API Token":              regexp.MustCompile(`(?i)linode[_-]?(?:api)?[_-]?token\s*[:=]\s*["']?[a-f0-9]{64}["']?`),
        "Vultr API Key":                 regexp.MustCompile(`(?i)vultr[_-]?api[_-]?key\s*[:=]\s*["']?[A-Z0-9]{36}["']?`),
        "Hetzner API Token":             regexp.MustCompile(`(?i)hetzner[_-]?(?:api)?[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9]{64}["']?`),
        "Oracle Cloud API Key":          regexp.MustCompile(`(?i)oci[_-]?api[_-]?key\s*[:=]\s*["']?-----BEGIN (?:RSA )?PRIVATE KEY-----`),
        "IBM Cloud API Key":             regexp.MustCompile(`(?i)ibm[_-]?(?:cloud)?[_-]?api[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{44}["']?`),
        "NPM Access Token":              regexp.MustCompile(`npm_[a-zA-Z0-9]{36}`),
        "PyPI API Token":                regexp.MustCompile(`pypi-[a-zA-Z0-9_-]{100,}`),
        "NuGet API Key":                 regexp.MustCompile(`oy2[a-z0-9]{43}`),
        "RubyGems API Key":              regexp.MustCompile(`rubygems_[a-f0-9]{48}`),
        "CircleCI Token":                regexp.MustCompile(`(?i)circle[_-]?(?:ci)?[_-]?token\s*[:=]\s*["']?[a-f0-9]{40}["']?`),
        "Travis CI Token":               regexp.MustCompile(`(?i)travis[_-]?(?:ci)?[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9]{22}["']?`),
        "Jenkins API Token":             regexp.MustCompile(`(?i)jenkins[_-]?(?:api)?[_-]?token\s*[:=]\s*["']?[a-f0-9]{32,}["']?`),
        "Bitbucket App Password":        regexp.MustCompile(`(?i)bitbucket[_-]?(?:app)?[_-]?(?:password|secret)\s*[:=]\s*["']?[a-zA-Z0-9]{18,}["']?`),
        "Codecov Token":                 regexp.MustCompile(`(?i)codecov[_-]?token\s*[:=]\s*["']?[a-f0-9-]{36}["']?`),
        "Vercel Token":                  regexp.MustCompile(`(?i)vercel[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9]{24}["']?`),
        "Netlify Token":                 regexp.MustCompile(`(?i)netlify[_-]?(?:auth)?[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9_-]{40,}["']?`),
        "Vault Token":                   regexp.MustCompile(`(?i)(?:vault[_-]?token|hvs)\s*[:=]?\s*["']?(?:hvs\.)?[a-zA-Z0-9_-]{24,}["']?`),
        "Kubernetes Token":              regexp.MustCompile(`eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
        "Docker Registry Password":      regexp.MustCompile(`(?i)docker[_-]?(?:registry)?[_-]?(?:password|pass|pwd)\s*[:=]\s*["']?[^\s"']{8,}["']?`),
        "Terraform Cloud Token":         regexp.MustCompile(`(?i)(?:tfe|terraform)[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9]{14}\.[a-zA-Z0-9_-]{67}["']?`),
        "Pulumi Access Token":           regexp.MustCompile(`pul-[a-f0-9]{40}`),
        "Adyen API Key":                 regexp.MustCompile(`(?i)adyen[_-]?api[_-]?key\s*[:=]\s*["']?AQE[a-zA-Z0-9_-]{50,}["']?`),
        "Klarna API Key":                regexp.MustCompile(`(?i)klarna[_-]?api[_-]?(?:key|secret)\s*[:=]\s*["']?[a-zA-Z0-9_-]{30,}["']?`),
        "Razorpay Key":                  regexp.MustCompile(`rzp_(?:live|test)_[a-zA-Z0-9]{14}`),
        "Coinbase API Secret":           regexp.MustCompile(`(?i)coinbase[_-]?(?:api)?[_-]?secret\s*[:=]\s*["']?[a-zA-Z0-9]{64}["']?`),
        "Binance API Secret":            regexp.MustCompile(`(?i)binance[_-]?(?:api)?[_-]?secret\s*[:=]\s*["']?[a-zA-Z0-9]{64}["']?`),
        "Twilio Auth Token":             regexp.MustCompile(`(?i)twilio[_-]?auth[_-]?token\s*[:=]\s*["']?[a-f0-9]{32}["']?`),
        "Pusher Secret":                 regexp.MustCompile(`(?i)pusher[_-]?(?:app)?[_-]?secret\s*[:=]\s*["']?[a-f0-9]{20}["']?`),
        "Vonage API Secret":             regexp.MustCompile(`(?i)(?:vonage|nexmo)[_-]?(?:api)?[_-]?secret\s*[:=]\s*["']?[a-zA-Z0-9]{16}["']?`),
        "Plivo Auth Token":              regexp.MustCompile(`(?i)plivo[_-]?auth[_-]?(?:token|id)\s*[:=]\s*["']?[a-zA-Z0-9]{40,}["']?`),
        "MessageBird API Key":           regexp.MustCompile(`(?i)messagebird[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9]{25}["']?`),
        "Intercom Access Token":         regexp.MustCompile(`(?i)intercom[_-]?(?:access)?[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9=_-]{60,}["']?`),
        "Zendesk API Token":             regexp.MustCompile(`(?i)zendesk[_-]?(?:api)?[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9]{40}["']?`),
        "Algolia Admin API Key":         regexp.MustCompile(`(?i)algolia[_-]?(?:admin)?[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-f0-9]{32}["']?`),
        "Elasticsearch API Key":         regexp.MustCompile(`(?i)(?:elastic|es)[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{50,}["']?`),
        "Mixpanel API Secret":           regexp.MustCompile(`(?i)mixpanel[_-]?(?:api)?[_-]?secret\s*[:=]\s*["']?[a-f0-9]{32}["']?`),
        "Amplitude API Key":             regexp.MustCompile(`(?i)amplitude[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-f0-9]{32}["']?`),
        "Segment Write Key":             regexp.MustCompile(`(?i)segment[_-]?(?:write)?[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9]{32}["']?`),
        "New Relic License Key":         regexp.MustCompile(`(?i)new[_-]?relic[_-]?license[_-]?key\s*[:=]\s*["']?[a-f0-9]{40}["']?`),
        "New Relic API Key":             regexp.MustCompile(`NRAK-[A-Z0-9]{27}`),
        "New Relic Insights Key":        regexp.MustCompile(`NRI[IQ]-[a-zA-Z0-9_-]{32}`),
        "Loggly Token":                  regexp.MustCompile(`(?i)loggly[_-]?(?:customer)?[_-]?token\s*[:=]\s*["']?[a-f0-9-]{36}["']?`),
        "Splunk HEC Token":              regexp.MustCompile(`(?i)splunk[_-]?(?:hec)?[_-]?token\s*[:=]\s*["']?[a-f0-9-]{36}["']?`),
        "Sumo Logic Access Key":         regexp.MustCompile(`(?i)sumo[_-]?logic[_-]?(?:access)?[_-]?(?:key|id)\s*[:=]\s*["']?su[a-zA-Z0-9]{12}["']?`),
        "Grafana API Key":               regexp.MustCompile(`eyJr[a-zA-Z0-9_-]{50,}={0,2}`),
        "PagerDuty API Key":             regexp.MustCompile(`(?i)pagerduty[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9+/=_-]{20}["']?`),
        "Supabase Service Role Key":     regexp.MustCompile(`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`),
        "Firebase Admin SDK Key":        regexp.MustCompile(`(?i)firebase[_-]?(?:admin)?[_-]?sdk[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{100,}["']?`),
        "Auth0 Client Secret":           regexp.MustCompile(`(?i)auth0[_-]?(?:client)?[_-]?secret\s*[:=]\s*["']?[a-zA-Z0-9_-]{64,}["']?`),
        "Okta API Token Alt":            regexp.MustCompile(`(?i)okta[_-]?(?:api)?[_-]?token\s*[:=]\s*["']?00[a-zA-Z0-9_-]{40}["']?`),
        "Cloudinary Secret":             regexp.MustCompile(`(?i)cloudinary[_-]?(?:api)?[_-]?secret\s*[:=]\s*["']?[a-zA-Z0-9_-]{27}["']?`),
        "Cloudinary URL":                regexp.MustCompile(`cloudinary://[0-9]+:[a-zA-Z0-9_-]+@[a-z]+`),
        "Backblaze Application Key":     regexp.MustCompile(`(?i)b2[_-]?(?:application)?[_-]?key\s*[:=]\s*["']?K[a-zA-Z0-9]{30,}["']?`),
        "Wasabi Access Key":             regexp.MustCompile(`(?i)wasabi[_-]?(?:access)?[_-]?key\s*[:=]\s*["']?[A-Z0-9]{20}["']?`),
        "LaunchDarkly SDK Key":          regexp.MustCompile(`(?i)(?:ld)?[_-]?sdk[_-]?key\s*[:=]\s*["']?sdk-[a-f0-9-]{36}["']?`),
        "LaunchDarkly API Key":          regexp.MustCompile(`(?i)launchdarkly[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?api-[a-f0-9-]{36}["']?`),
        "Split.io API Key":              regexp.MustCompile(`(?i)split[_-]?(?:io)?[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9]{50,}["']?`),
        "Statsig Secret":                regexp.MustCompile(`(?i)statsig[_-]?(?:secret)?[_-]?key\s*[:=]\s*["']?secret-[a-zA-Z0-9]{50,}["']?`),
        "GitLab Pipeline Token":         regexp.MustCompile(`glptt-[a-f0-9]{40}`),
        "GitLab Runner Token":           regexp.MustCompile(`GR1348941[a-zA-Z0-9_-]{20}`),
        "GitHub App Private Key":        regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----`),
        "Bitbucket OAuth Secret":        regexp.MustCompile(`(?i)bitbucket[_-]?(?:oauth)?[_-]?secret\s*[:=]\s*["']?[a-zA-Z0-9]{32,}["']?`),
        "Contentful Management Token":   regexp.MustCompile(`CFPAT-[a-zA-Z0-9_-]{43}`),
        "Contentful Delivery Token":     regexp.MustCompile(`(?i)contentful[_-]?(?:delivery)?[_-]?token\s*[:=]\s*["']?[a-zA-Z0-9_-]{43}["']?`),
        "Sanity Token":                  regexp.MustCompile(`sk[a-zA-Z0-9]{32,}`),
        "Strapi API Token":              regexp.MustCompile(`(?i)strapi[_-]?(?:api)?[_-]?token\s*[:=]\s*["']?[a-f0-9]{256}["']?`),
        "Postmark Server Token":         regexp.MustCompile(`(?i)postmark[_-]?(?:server)?[_-]?token\s*[:=]\s*["']?[a-f0-9-]{36}["']?`),
        "SparkPost API Key":             regexp.MustCompile(`(?i)sparkpost[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-f0-9]{40}["']?`),
        "Mailjet API Secret":            regexp.MustCompile(`(?i)mailjet[_-]?(?:api)?[_-]?secret\s*[:=]\s*["']?[a-f0-9]{32}["']?`),
        "Mandrill API Key":              regexp.MustCompile(`(?i)mandrill[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{22}["']?`),
        "Customer.io API Key":           regexp.MustCompile(`(?i)customer[_-]?io[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-f0-9]{32}["']?`),
        "Mapbox Secret Token":           regexp.MustCompile(`sk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9_-]{22,}`),
        "Here API Key":                  regexp.MustCompile(`(?i)here[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9_-]{43}["']?`),
        "TomTom API Key":                regexp.MustCompile(`(?i)tomtom[_-]?(?:api)?[_-]?key\s*[:=]\s*["']?[a-zA-Z0-9]{32}["']?`),
        "LinkedIn Client Secret":        regexp.MustCompile(`(?i)linkedin[_-]?(?:client)?[_-]?secret\s*[:=]\s*["']?[a-zA-Z0-9]{16}["']?`),
        "Spotify Client Secret":         regexp.MustCompile(`(?i)spotify[_-]?(?:client)?[_-]?secret\s*[:=]\s*["']?[a-f0-9]{32}["']?`),
        "Dropbox App Secret":            regexp.MustCompile(`(?i)dropbox[_-]?(?:app)?[_-]?secret\s*[:=]\s*["']?[a-z0-9]{15}["']?`),
        "Private Key Inline":            regexp.MustCompile(`(?i)(?:private[_-]?key|priv[_-]?key)\s*[:=]\s*["'][a-zA-Z0-9+/=\n]{100,}["']`),
        "Password Hardcoded":            regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["'][^"']{8,50}["']`),
        "Secret Key Hardcoded":          regexp.MustCompile(`(?i)(?:secret[_-]?key|signing[_-]?key|encryption[_-]?key)\s*[:=]\s*["'][a-zA-Z0-9+/=_-]{20,}["']`),
    }

    asciiArt = `
         ________             __         
     __ / / __/ /  __ _____  / /____ ____
    / // /\ \/ _ \/ // / _ \/ __/ -_) __/
    \___/___/_//_/\_,_/_//_/\__/\__/_/  

     ` + version + `                         Created by cc1a2b
    `
)

// progressReader wraps an io.Reader to track download progress
type progressReader struct {
    reader     io.Reader
    total      int64
    current    int64
    lastUpdate time.Time
    onProgress func(int64)
}

func (pr *progressReader) Read(p []byte) (int, error) {
    n, err := pr.reader.Read(p)
    pr.current += int64(n)
    
    // Only update progress every 100ms to avoid too many updates
    if pr.onProgress != nil && time.Since(pr.lastUpdate) > 100*time.Millisecond {
        pr.onProgress(pr.current)
        pr.lastUpdate = time.Now()
    }
    
    return n, err
}

// flagList is a custom type for handling multiple header flags
type flagList []string

func (f *flagList) String() string {
    return strings.Join(*f, ", ")
}

func (f *flagList) Set(value string) error {
    *f = append(*f, value)
    return nil
}

// Config holds all configuration options
type Config struct {
    // Basic options
    URL, List, JSFile, Output, Regex, Cookies, Proxy string
    Threads                                           int
    Quiet, Help, Update, ExtractEndpoints, SkipTLS, FoundOnly bool
    
    // Advanced HTTP
    Headers    []string // Custom HTTP headers
    UserAgent  string   // Custom User-Agent (single string or randomly selected from file)
    UserAgents []string // List of User-Agents (when loaded from file)
    RateLimit int      // Delay between requests (ms)
    Timeout    int      // Request timeout (seconds)
    Retry      int      // Retry failed requests
    
    // JS Analysis
    Deobfuscate, SourceMap, Eval, ObfsDetect bool
    
    // Security Analysis
    Secrets, Tokens, Params, ParamURLs, Internal, GraphQL, Bypass, Firebase, Links bool
    
    // Crawling & Scope
    CrawlDepth int    // Recursive JS crawling depth
    Domain     string // Scope to specific domain
    Ext        string // Match specific JS file extensions
    
    // Output
    JSON, CSV, Verbose, Burp bool
}

func main() {
    var (
        url, list, jsFile, output, regex, cookies, proxy string
        threads                                           int
        quiet, help, update, extractEndpoints, skipTLS, foundOnly bool
    )
    
    // Advanced HTTP
    var headers flagList
    var userAgent string
    var rateLimit, timeout, retry int
    
    // JS Analysis
    var deobfuscate, sourceMap, eval, obfsDetect bool
    
    // Security Analysis
    var secrets, tokens, params, paramURLs, internal, graphql, bypass, firebase, links bool
    
    // Crawling & Scope
    var crawlDepth int
    var domain, ext string
    
    // Output
    var jsonOut, csvOut, verbose, burp bool

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
    
    // Advanced HTTP flags
    flag.Var(&headers, "H", "Custom HTTP headers (repeatable, format: 'Key: Value')")
    flag.Var(&headers, "header", "Custom HTTP headers (repeatable, format: 'Key: Value')")
    flag.StringVar(&userAgent, "U", "", "Custom User-Agent string or path to file containing user agents (one per line)")
    flag.StringVar(&userAgent, "user-agent", "", "Custom User-Agent string or path to file containing user agents (one per line)")
    flag.IntVar(&rateLimit, "R", 0, "Delay between requests (ms)")
    flag.IntVar(&rateLimit, "rate-limit", 0, "Delay between requests (ms)")
    flag.IntVar(&timeout, "T", 30, "Request timeout (seconds)")
    flag.IntVar(&timeout, "timeout", 30, "Request timeout (seconds)")
    flag.IntVar(&retry, "y", 2, "Retry failed requests")
    flag.IntVar(&retry, "retry", 2, "Retry failed requests")
    
    // JS Analysis flags
    flag.BoolVar(&deobfuscate, "d", false, "Deobfuscate minified/obfuscated code")
    flag.BoolVar(&deobfuscate, "deobfuscate", false, "Deobfuscate minified/obfuscated code")
    flag.BoolVar(&sourceMap, "m", false, "Parse source maps for original JS")
    flag.BoolVar(&sourceMap, "sourcemap", false, "Parse source maps for original JS")
    flag.BoolVar(&eval, "e", false, "Analyze eval() & dynamic code")
    flag.BoolVar(&eval, "eval", false, "Analyze eval() & dynamic code")
    flag.BoolVar(&obfsDetect, "z", false, "Detect obfuscation techniques")
    flag.BoolVar(&obfsDetect, "obfs-detect", false, "Detect obfuscation techniques")
    
    // Security Analysis flags
    flag.BoolVar(&secrets, "s", false, "API keys, tokens, credentials detection")
    flag.BoolVar(&secrets, "secrets", false, "API keys, tokens, credentials detection")
    flag.BoolVar(&tokens, "x", false, "JWT/auth tokens extraction")
    flag.BoolVar(&tokens, "tokens", false, "JWT/auth tokens extraction")
    flag.BoolVar(&params, "P", false, "Hidden parameters discovery")
    flag.BoolVar(&params, "params", false, "Hidden parameters discovery")
    flag.BoolVar(&paramURLs, "PU", false, "Advanced URL parameter extraction with base URLs")
    flag.BoolVar(&paramURLs, "param-urls", false, "Advanced URL parameter extraction with base URLs")
    flag.BoolVar(&internal, "i", false, "Internal/private endpoints only")
    flag.BoolVar(&internal, "internal", false, "Internal/private endpoints only")
    flag.BoolVar(&graphql, "g", false, "GraphQL endpoints & queries")
    flag.BoolVar(&graphql, "graphql", false, "GraphQL endpoints & queries")
    flag.BoolVar(&bypass, "B", false, "WAF bypass patterns detection")
    flag.BoolVar(&bypass, "bypass", false, "WAF bypass patterns detection")
    flag.BoolVar(&firebase, "F", false, "Firebase config/secrets detection")
    flag.BoolVar(&firebase, "firebase", false, "Firebase config/secrets detection")
    flag.BoolVar(&links, "L", false, "Extract all links/URLs from JS")
    flag.BoolVar(&links, "links", false, "Extract all links/URLs from JS")
    
    // Crawling & Scope flags
    flag.IntVar(&crawlDepth, "w", 1, "Recursive JS crawling depth")
    flag.IntVar(&crawlDepth, "crawl", 1, "Recursive JS crawling depth")
    flag.StringVar(&domain, "D", "", "Scope to specific domain")
    flag.StringVar(&domain, "domain", "", "Scope to specific domain")
    flag.StringVar(&ext, "E", "", "Match specific JS file extensions (comma-separated)")
    flag.StringVar(&ext, "ext", "", "Match specific JS file extensions (comma-separated)")
    
    // Output flags
    flag.BoolVar(&jsonOut, "j", false, "Structured JSON output")
    flag.BoolVar(&jsonOut, "json", false, "Structured JSON output")
    flag.BoolVar(&csvOut, "C", false, "CSV for Excel/Sheets import")
    flag.BoolVar(&csvOut, "csv", false, "CSV for Excel/Sheets import")
    flag.BoolVar(&verbose, "v", false, "Detailed analysis output")
    flag.BoolVar(&verbose, "verbose", false, "Detailed analysis output")
    flag.BoolVar(&burp, "n", false, "Burp Suite export format")
    flag.BoolVar(&burp, "burp", false, "Burp Suite export format")


    flag.Parse()

    // Process User-Agent: check if it's a file path or a string
    var userAgentsList []string
    finalUserAgent := userAgent
    if userAgent != "" {
        // Check if it looks like a file path (contains path separators or common file extensions)
        if strings.Contains(userAgent, "/") || strings.Contains(userAgent, "\\") || 
           strings.HasSuffix(userAgent, ".txt") || strings.HasSuffix(userAgent, ".list") {
            // Try to read as file
            if fileInfo, err := os.Stat(userAgent); err == nil && !fileInfo.IsDir() {
                // It's a file, read user agents from it
                file, err := os.Open(userAgent)
                if err == nil {
                    defer file.Close()
                    scanner := bufio.NewScanner(file)
                    for scanner.Scan() {
                        line := strings.TrimSpace(scanner.Text())
                        if line != "" && !strings.HasPrefix(line, "#") {
                            userAgentsList = append(userAgentsList, line)
                        }
                    }
                    if len(userAgentsList) > 0 {
                        // Select a random user agent from the list
                        rand.Seed(time.Now().UnixNano())
                        finalUserAgent = userAgentsList[rand.Intn(len(userAgentsList))]
                        if !quiet {
                            fmt.Printf("[%sINFO%s] Loaded %d user agents from file, using: %s\n", 
                                colors["CYAN"], colors["NC"], len(userAgentsList), finalUserAgent)
                        }
                    } else {
                        if !quiet {
                            fmt.Printf("[%sWARN%s] User-Agent file is empty or contains no valid entries, using as string\n", 
                                colors["YELLOW"], colors["NC"])
                        }
                    }
                } else {
                    if !quiet {
                        fmt.Printf("[%sWARN%s] Could not read User-Agent file, using as string: %v\n", 
                            colors["YELLOW"], colors["NC"], err)
                    }
                }
            }
        }
    }

    // Create config object
    config := Config{
        URL: url, List: list, JSFile: jsFile, Output: output, Regex: regex,
        Cookies: cookies, Proxy: proxy, Threads: threads,
        Quiet: quiet, Help: help, Update: update, ExtractEndpoints: extractEndpoints,
        SkipTLS: skipTLS, FoundOnly: foundOnly,
        Headers: headers, UserAgent: finalUserAgent, UserAgents: userAgentsList, RateLimit: rateLimit,
        Timeout: timeout, Retry: retry,
        Deobfuscate: deobfuscate, SourceMap: sourceMap, Eval: eval, ObfsDetect: obfsDetect,
        Secrets: secrets, Tokens: tokens, Params: params, ParamURLs: paramURLs, Internal: internal,
        GraphQL: graphql, Bypass: bypass, Firebase: firebase, Links: links,
        CrawlDepth: crawlDepth, Domain: domain, Ext: ext,
        JSON: jsonOut, CSV: csvOut, Verbose: verbose, Burp: burp,
    }

    if help {
        customHelp()
        return
    }

    if update {
        updateTool()
        return
    }

    if config.URL == "" && config.List == "" && config.JSFile == "" {
        if isInputFromStdin() {
            // Show ASCII art before processing stdin if not quiet
            if !config.Quiet {
                time.Sleep(100 * time.Millisecond)
                displayAsciiArt()
            }
            
            // Read all stdin content
            stdinContent, err := ioutil.ReadAll(os.Stdin)
            if err != nil {
                if !config.Quiet {
                    fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
                }
                return
            }
            
            content := string(stdinContent)
            
            // Check if it looks like a list of URLs (each line is a URL)
            lines := strings.Split(content, "\n")
            urlCount := 0
            jsLineCount := 0
            totalLines := 0
            
            for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" {
                    continue
                }
                totalLines++
                
                // Check if line looks like a URL
                if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
                    urlCount++
                }
                // Check if line looks like JavaScript
                if strings.Contains(line, "function") || 
                   strings.Contains(line, "const ") || 
                   strings.Contains(line, "let ") || 
                   strings.Contains(line, "var ") ||
                   strings.Contains(line, "URLSearchParams") ||
                   strings.Contains(line, ".get(") ||
                   strings.Contains(line, "fetch(") ||
                   strings.Contains(line, "axios.") ||
                   strings.Contains(line, "//") ||
                   strings.Contains(line, "/*") {
                    jsLineCount++
                }
            }
            
            // Determine if it's JavaScript or URL list
            // Priority: If most lines are URLs, always treat as URL list (process each URL)
            isJavaScript := false
            
            if totalLines > 0 {
                urlRatio := float64(urlCount) / float64(totalLines)
                
                // If more than 50% are URLs, treat as URL list (process each URL individually)
                if urlRatio > 0.5 {
                    isJavaScript = false
                } else if config.ParamURLs || config.Params {
                    // Using -PU/-P flags, check if it's actually JS code
                    if jsLineCount > 5 || 
                       strings.Contains(content, "function ") || 
                       strings.Contains(content, "const urlParams") ||
                       strings.Contains(content, "new URLSearchParams") ||
                       strings.Contains(content, "URLSearchParams.get") {
                        // Clear JavaScript patterns
                        isJavaScript = true
                    } else {
                        // Default: treat as JavaScript when using -PU/-P
                        isJavaScript = true
                    }
                } else {
                    // Without -PU/-P, check if it's JavaScript
                    if jsLineCount > 5 || strings.Contains(content, "function ") {
                        isJavaScript = true
                    }
                }
            }
            
            if isJavaScript {
                // Process as JavaScript content directly
                source := "stdin"
                bodyBytes := []byte(content)
                
                if config.ParamURLs {
                    paramURLs := extractURLParamsWithBaseURLs(content, source)
                    if len(paramURLs) > 0 {
                        globalSeenMutex.Lock()
                        globalFoundAny = true // Mark that we found something
                        for _, paramURL := range paramURLs {
                            if !globalSeenAll[paramURL] {
                                globalSeenAll[paramURL] = true
                                fmt.Println(paramURL)
                            }
                        }
                        globalSeenMutex.Unlock()
                    }
                } else if config.ExtractEndpoints {
                    endpoints := extractEndpointsFromContent(content, config.Regex, "")
                    displayEndpoints(endpoints, source)
                } else {
                    // Process as sensitive data search - use reportMatchesWithConfig directly
                    reportMatchesWithConfig(source, bodyBytes, &config)
                }
            } else {
                // Treat each line as URL/file path (old behavior)
                scanner := bufio.NewScanner(strings.NewReader(content))
                for scanner.Scan() {
                    inputURL := strings.TrimSpace(scanner.Text())
                    if inputURL == "" {
                        continue
                    }
                    
                    if config.ExtractEndpoints {
                        processInputsForEndpointsWithConfig(inputURL, &config)
                    } else {
                        processInputsWithConfig(inputURL, &config)
                    }
                }
                if err := scanner.Err(); err != nil {
                    if !config.Quiet {
                        fmt.Fprintln(os.Stderr, "Error reading from stdin:", err)
                    }
                }
            }
            return
        }
        customHelp()
        os.Exit(1)
    }

    if !config.Quiet {
        time.Sleep(100 * time.Millisecond)
        displayAsciiArt()
    }

    if config.Quiet {
        disableColors()
    }

    if config.JSFile != "" {
        if config.ExtractEndpoints {
            processJSFileForEndpointsWithConfig(config.JSFile, &config)
        } else {
            processJSFileWithConfig(config.JSFile, &config)
        }
        return 
    }

    if config.ExtractEndpoints && (config.URL != "" || config.List != "") {
        processInputsForEndpointsWithConfig(config.URL, &config)
    } else {
        processInputsWithConfig(config.URL, &config)
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
    fmt.Println("Basic Options:")
    fmt.Println("  -t, --threads INT             Number of concurrent threads (default: 5)")
    fmt.Println("  -c, --cookies <cookies>      Authentication cookies for protected resources")
    fmt.Println("  -p, --proxy host:port        HTTP proxy configuration (e.g., 127.0.0.1:8080 for Burp Suite)")
    fmt.Println("  -q, --quiet                  Suppress ASCII art output")
    fmt.Println("  -o, --output FILENAME.txt    Output file path")
    fmt.Println("  -r, --regex <pattern>        RegEx for filtering results (endpoints and sensitive data)")
    fmt.Println("  --update, --up               Update the tool to latest version")
    fmt.Println("  -ep, --end-point             Extract endpoints from JavaScript files")
    fmt.Println("  -k, --skip-tls               Skip TLS certificate verification")
    fmt.Println("  -fo, --found-only            Only show results when sensitive data is found (hide MISSING messages)")
    fmt.Println()
    fmt.Println("HTTP Configuration:")
    fmt.Println("  -H, --header \"Key: Value\"    Custom HTTP headers (repeatable, including Auth)")
    fmt.Println("  -U, --user-agent UA          Custom User-Agent string or file path (one per line)")
    fmt.Println("  -R, --rate-limit MS          Request rate limiting delay (milliseconds)")
    fmt.Println("  -T, --timeout SEC            HTTP request timeout (seconds)")
    fmt.Println("  -y, --retry INT              Retry attempts for failed requests (default: 2)")
    fmt.Println()
    fmt.Println("JavaScript Analysis:")
    fmt.Println("  -d, --deobfuscate            Deobfuscate minified and obfuscated JavaScript")
    fmt.Println("  -m, --sourcemap              Parse source maps for original code analysis")
    fmt.Println("  -e, --eval                   Analyze dynamic code execution (eval, Function)")
    fmt.Println("  -z, --obfs-detect            Detect code obfuscation patterns and techniques")
    fmt.Println()
    fmt.Println("Security Analysis:")
    fmt.Println("  -s, --secrets                Detect API keys, tokens, and credentials")
    fmt.Println("  -x, --tokens                 Extract JWT and authentication tokens")
    fmt.Println("  -P, --params                 Discover hidden parameters and variables")
    fmt.Println("  -PU, --param-urls            Advanced parameter extraction with URL context")
    fmt.Println("  -i, --internal               Filter for internal/private endpoints")
    fmt.Println("  -g, --graphql                Analyze GraphQL endpoints and queries")
    fmt.Println("  -B, --bypass                 Detect WAF bypass patterns and techniques")
    fmt.Println("  -F, --firebase               Analyze Firebase configurations and keys")
    fmt.Println("  -L, --links                  Extract and analyze all embedded links")
    fmt.Println()
    fmt.Println("Scope & Discovery:")
    fmt.Println("  -w, --crawl DEPTH            Recursive JavaScript discovery depth (default: 1)")
    fmt.Println("  -D, --domain DOMAIN          Limit analysis to specific domain")
    fmt.Println("  -E, --ext                    Filter by JavaScript file extensions")
    fmt.Println()
    fmt.Println("Output Formats:")
    fmt.Println("  -j, --json                   Structured JSON output format")
    fmt.Println("  -C, --csv                    CSV format for spreadsheet analysis")
    fmt.Println("  -v, --verbose                Detailed analysis and debug output")
    fmt.Println("  -n, --burp                   Burp Suite compatible export format")
    fmt.Println("  -h, --help                   Display this help message")
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
    // Create minimal config for backward compatibility
    config := &Config{
        Regex: regex,
    }
    processJSFileWithConfig(jsFile, config)
}


func processInputs(url, list, output, regex, cookie, proxy string, threads int, skipTLS, foundOnly bool) {
    // Create config for backward compatibility
    config := &Config{
        URL: url, List: list, Output: output, Regex: regex,
        Cookies: cookie, Proxy: proxy, Threads: threads,
        SkipTLS: skipTLS, FoundOnly: foundOnly,
        Timeout: 30, Retry: 2,
    }
    processInputsWithConfig(url, config)
    return
}

func processInputsOld(url, list, output, regex, cookie, proxy string, threads int, skipTLS, foundOnly bool) {
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
                // Create minimal config for each request
                config := &Config{
                    Regex: regex, Cookies: cookie, Proxy: proxy,
                    SkipTLS: skipTLS, FoundOnly: foundOnly,
                    Timeout: 30, Retry: 1,
                }
                _, sensitiveData := searchForSensitiveDataWithConfig(u, config)

                // Don't print sensitive data if ParamURLs flag is set (user only wants URL params)
                if !config.ParamURLs {
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
    
    // Print buffered MISSING messages only if no findings were made
    // This is for the old/legacy function - always clear buffer
    globalSeenMutex.Lock()
    foundAny := globalFoundAny
    globalSeenMutex.Unlock()
    
    if !foundAny && !foundOnly {
        missingMutex.Lock()
        for _, msg := range missingMessages {
            fmt.Printf("[%sMISSING%s] No sensitive data found at: %s\n", colors["BLUE"], colors["NC"], msg)
        }
        missingMessages = missingMessages[:0] // Clear the buffer
        missingMutex.Unlock()
    } else {
        // Clear the buffer if findings were made
        missingMutex.Lock()
        missingMessages = missingMessages[:0]
        missingMutex.Unlock()
    }
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


// isTLSCanceledError checks if an error is a TLS cancellation error (common with proxy interception)
func isTLSCanceledError(err error) bool {
    if err == nil {
        return false
    }
    errStr := strings.ToLower(err.Error())
    // Check for various TLS and connection errors that can occur with proxy interception
    return strings.Contains(errStr, "tls: user canceled") || 
           strings.Contains(errStr, "user canceled") ||
           strings.Contains(errStr, "tls: handshake failure") ||
           strings.Contains(errStr, "remote error: tls") ||
           strings.Contains(errStr, "connection reset") ||
           err == io.EOF // EOF can occur when proxy closes connection
}

// isJavaScriptContentType checks if the Content-Type header indicates JavaScript content
func isJavaScriptContentType(contentType string) bool {
    if contentType == "" {
        return false
    }
    contentType = strings.ToLower(strings.TrimSpace(contentType))
    // Remove charset and other parameters (e.g., "application/javascript; charset=utf-8")
    if idx := strings.Index(contentType, ";"); idx != -1 {
        contentType = contentType[:idx]
    }
    contentType = strings.TrimSpace(contentType)
    
    // Common JavaScript MIME types
    jsTypes := []string{
        "application/javascript",
        "application/x-javascript",
        "text/javascript",
        "text/ecmascript",
        "application/ecmascript",
    }
    
    for _, jsType := range jsTypes {
        if contentType == jsType {
            return true
        }
    }
    
    return false
}

// isValidStatusCode checks if the HTTP status code indicates a successful response
func isValidStatusCode(statusCode int) bool {
    // Accept 2xx status codes (successful responses)
    return statusCode >= 200 && statusCode < 300
}

// isNonJavaScriptContentType checks if Content-Type indicates non-JavaScript content that should be filtered out
func isNonJavaScriptContentType(contentType string) bool {
    if contentType == "" {
        return false // Unknown content type, check URL extension instead
    }
    contentType = strings.ToLower(strings.TrimSpace(contentType))
    // Remove charset and other parameters (e.g., "text/html; charset=utf-8")
    if idx := strings.Index(contentType, ";"); idx != -1 {
        contentType = contentType[:idx]
    }
    contentType = strings.TrimSpace(contentType)
    
    // Non-JavaScript content types to filter out
    nonJSTypes := []string{
        // HTML
        "text/html",
        "application/xhtml+xml",
        // CSS
        "text/css",
        // Plain text
        "text/plain",
        // JSON (unless it's a JS file with wrong content-type)
        "application/json",
        // XML
        "text/xml",
        "application/xml",
        "application/rss+xml",
        "application/atom+xml",
        // Images
        "image/jpeg",
        "image/jpg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/svg+xml",
        "image/x-icon",
        "image/vnd.microsoft.icon",
        // Fonts
        "font/woff",
        "font/woff2",
        "application/font-woff",
        "application/font-woff2",
        // Video
        "video/mp4",
        "video/webm",
        "video/ogg",
        // Audio
        "audio/mpeg",
        "audio/ogg",
        "audio/wav",
        // Documents
        "application/pdf",
        "application/msword",
        "application/vnd.ms-excel",
        // Other
        "application/octet-stream",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    }
    
    for _, nonJSType := range nonJSTypes {
        if contentType == nonJSType {
            return true
        }
    }
    
    // Filter out any text/* types that aren't JavaScript
    if strings.HasPrefix(contentType, "text/") && !isJavaScriptContentType(contentType) {
        return true
    }
    
    return false
}

// shouldProcessResponse checks if the response should be processed based on Content-Type and status code
func shouldProcessResponse(resp *http.Response, urlStr string, config *Config) bool {
    // Check status code first - silently skip invalid status codes
    if !isValidStatusCode(resp.StatusCode) {
        return false
    }
    
    // Check Content-Type
    contentType := resp.Header.Get("Content-Type")
    
    // If Content-Type explicitly indicates non-JavaScript, skip it
    if isNonJavaScriptContentType(contentType) {
        return false
    }
    
    // If Content-Type is JavaScript, process it
    if isJavaScriptContentType(contentType) {
        return true
    }
    
    // If Content-Type is unknown or missing, check URL extension as fallback
    urlLower := strings.ToLower(urlStr)
    hasJSExtension := strings.HasSuffix(urlLower, ".js") || 
                     strings.Contains(urlLower, ".js?") ||
                     strings.Contains(urlLower, ".js&") ||
                     strings.Contains(urlLower, ".js#")
    
    // Only process if URL has .js extension
    return hasJSExtension
}

func searchForSensitiveData(urlStr, regex, cookie, proxy string, skipTLS, foundOnly bool) (string, map[string][]string) {
    var client *http.Client

    transport := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: skipTLS},
        DisableKeepAlives: false,
        MaxIdleConns: 10,
        IdleConnTimeout: 30 * time.Second,
    }
    
    var clientTimeout time.Duration = 30 * time.Second
    
    if proxy != "" {
        // Normalize proxy URL - add http:// if not present
        proxyURLStr := proxy
        if !strings.HasPrefix(proxy, "http://") && !strings.HasPrefix(proxy, "https://") {
            proxyURLStr = "http://" + proxy
        }
        
        proxyURL, err := url.Parse(proxyURLStr)
        if err != nil {
            fmt.Printf("Invalid proxy URL: %v\n", err)
            return urlStr, nil
        }
        transport.Proxy = http.ProxyURL(proxyURL)
        
        // When using proxy (like Burp), skip TLS verification to avoid certificate issues
        transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
        
        // Increase timeout for proxy connections (Burp interception may take time)
        clientTimeout = 60 * time.Second
    }
    
    client = &http.Client{
        Transport: transport,
        Timeout: clientTimeout,
    }

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
            // Suppress TLS user canceled errors when using proxy (Burp interception)
            if proxy == "" || !isTLSCanceledError(err) {
                // Only print if not using proxy or if it's a different error
            }
            return urlStr, nil
        }
        defer resp.Body.Close()

        // Filter: Only process JavaScript content (create minimal config for filtering)
        minimalConfig := &Config{Verbose: false}
        if !shouldProcessResponse(resp, urlStr, minimalConfig) {
            return urlStr, nil
        }

        // Try to read the body, even if there might be an error (partial reads are useful)
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            // Suppress TLS user canceled errors when using proxy (Burp may close connection)
            if proxy == "" || !isTLSCanceledError(err) {
                // Only show error if we got no data at all
                if len(body) == 0 {
                    fmt.Printf("Error reading response body: %v\n", err)
                    return urlStr, nil
                }
                // If we got some data, continue processing it despite the error
            } else if len(body) == 0 {
                // Proxy error and no data - silently return
                return urlStr, nil
            }
            // If we have data (even partial), continue to process it
        }

        // Process the body even if there was a read error (might have partial data)
        if len(body) > 0 {
            sensitiveData = reportMatches(urlStr, body, regexPatterns, regex, foundOnly)
        } else {
            sensitiveData = make(map[string][]string)
        }
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
        "info@", "career@", "careers@", "jobs@", "admin@", "support@", "contact@",
        "help@", "noreply@", "no-reply@", "test@", "demo@", "example@",
        "sales@", "marketing@", "press@", "media@", "feedback@", "hello@",
        "team@", "hr@", "legal@", "privacy@", "abuse@", "postmaster@",
        "webmaster@", "hostmaster@", "security@", "compliance@", "billing@",
        "service@", "newsletter@", "notifications@", "alerts@", "noemail@",
        "donotreply@", "do-not-reply@", "mailer@", "mail@", "email@",
        "integration@", "api@", "dev@", "developer@", "developers@",
    }

    unwantedDomains := []string{
        "example.com", "test.com", "localhost", "example.org", "example.net",
        "domain.com", "email.com", "mail.com", "yoursite.com", "yourdomain.com",
        "sentry.io", "sentry-next.wixpress.com",
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
        // Mark that we found something
        globalSeenMutex.Lock()
        globalFoundAny = true
        globalSeenMutex.Unlock()
    } else {
        // Buffer MISSING messages instead of printing immediately
        if !foundOnly {
            missingMutex.Lock()
            missingMessages = append(missingMessages, source)
            missingMutex.Unlock()
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
    
    
    goos := runtime.GOOS
    goarch := runtime.GOARCH
    
    binaryName = fmt.Sprintf("jshunter_%s_%s", goos, goarch)
    
    // First try to find platform-specific binary
    for _, asset := range release.Assets {
        if strings.Contains(asset.Name, goos) && strings.Contains(asset.Name, goarch) {
            downloadURL = asset.BrowserDownloadURL
            binaryName = asset.Name
            break
        }
    }
    
    // If no platform-specific binary found, look for generic binary
    if downloadURL == "" {
        for _, asset := range release.Assets {
            if asset.Name == "jshunter" || strings.HasPrefix(asset.Name, "jshunter") {
                downloadURL = asset.BrowserDownloadURL
                binaryName = asset.Name
                break
            }
        }
    }
    
    if downloadURL == "" {
        fmt.Printf("[%sERROR%s] No suitable binary found for your platform (%s_%s)\n", colors["RED"], colors["NC"], goos, goarch)
        fmt.Printf("[%sINFO%s] Please download manually from: https://github.com/cc1a2b/jshunter/releases/tag/%s\n", colors["YELLOW"], colors["NC"], latestVersion)
        return
    }
    
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
    
    // Get content length for progress bar
    contentLength := resp.ContentLength
    if contentLength <= 0 {
        contentLength = 0
    }
    
    // Create smart loader
    var binaryData []byte
    if contentLength > 0 {
        binaryData = make([]byte, 0, contentLength)
        reader := &progressReader{
            reader: resp.Body,
            total:  contentLength,
            onProgress: func(current int64) {
                // Smart progress bar like httpx
                progress := float64(current) / float64(contentLength)
                barWidth := 20
                filled := int(progress * float64(barWidth))
                
                bar := strings.Repeat("#", filled) + strings.Repeat(" ", barWidth-filled)
                percentage := int(progress * 100)
                
                // Format file size
                currentMB := float64(current) / (1024 * 1024)
                totalMB := float64(contentLength) / (1024 * 1024)
                
                fmt.Printf("\r[%sINFO%s] Downloading %s [%s%s%s] %d%% (%.1f/%.1f MB)", 
                    colors["BLUE"], colors["NC"], binaryName,
                    colors["BLUE"], bar, colors["NC"], 
                    percentage, currentMB, totalMB)
            },
        }
        
        binaryData, err = ioutil.ReadAll(reader)
        
        // Final progress update to show 100%
        if err == nil {
            progress := float64(reader.total) / float64(reader.total)
            barWidth := 20
            filled := int(progress * float64(barWidth))
            bar := strings.Repeat("#", filled) + strings.Repeat(" ", barWidth-filled)
            percentage := int(progress * 100)
            currentMB := float64(reader.total) / (1024 * 1024)
            totalMB := float64(reader.total) / (1024 * 1024)
            
            fmt.Printf("\r[%sINFO%s] Downloading %s [%s%s%s] %d%% (%.1f/%.1f MB)\n", 
                colors["BLUE"], colors["NC"], binaryName,
                colors["BLUE"], bar, colors["NC"], 
                percentage, currentMB, totalMB)
        } else {
            fmt.Println() // New line after loader
        }
    } else {
        binaryData, err = ioutil.ReadAll(resp.Body)
    }
    
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
    // Create config for backward compatibility
    config := &Config{
        URL: url, List: list, Output: output, Regex: regex,
        Cookies: cookie, Proxy: proxy, Threads: threads,
        SkipTLS: skipTLS, FoundOnly: foundOnly,
        Timeout: 30, Retry: 2,
    }
    processInputsForEndpointsWithConfig(url, config)
    return
}

func processInputsForEndpointsOld(url, list, output, regex, cookie, proxy string, threads int, skipTLS, foundOnly bool) {
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
                // Create minimal config for each request
                config := &Config{
                    Regex: regex, Cookies: cookie, Proxy: proxy,
                    SkipTLS: skipTLS,
                    Timeout: 30, Retry: 1,
                }
                endpoints := extractEndpointsFromURLWithConfig(u, config)
                
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
    // Create a minimal config for backward compatibility
    config := &Config{
        Proxy:   proxy,
        Cookies: cookie,
        SkipTLS: skipTLS,
        Timeout: 30,
        Retry:   1,
    }
    return extractEndpointsFromURLWithConfig(urlStr, config)
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

// createHTTPClientWithConfig creates an HTTP client with all advanced options
func createHTTPClientWithConfig(config *Config) *http.Client {
    transport := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLS},
        DisableKeepAlives: false,
        MaxIdleConns: 10,
        IdleConnTimeout: 30 * time.Second,
    }
    
    clientTimeout := time.Duration(config.Timeout) * time.Second
    
    if config.Proxy != "" {
        proxyURLStr := config.Proxy
        if !strings.HasPrefix(config.Proxy, "http://") && !strings.HasPrefix(config.Proxy, "https://") {
            proxyURLStr = "http://" + config.Proxy
        }
        
        proxyURL, err := url.Parse(proxyURLStr)
        if err != nil {
            fmt.Printf("[%sERROR%s] Invalid proxy URL %s: %v\n", colors["RED"], colors["NC"], proxyURLStr, err)
        } else {
            transport.Proxy = http.ProxyURL(proxyURL)
            transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
            clientTimeout = 60 * time.Second
            if config.Verbose {
                fmt.Printf("[%sINFO%s] Proxy configured: %s\n", colors["BLUE"], colors["NC"], proxyURLStr)
            }
        }
    }
    
    return &http.Client{
        Transport: transport,
        Timeout: clientTimeout,
    }
}

// makeRequestWithRetry makes an HTTP request with retry logic and rate limiting
func makeRequestWithRetry(client *http.Client, req *http.Request, config *Config) (*http.Response, error) {
    // Apply rate limiting
    if config.RateLimit > 0 {
        time.Sleep(time.Duration(config.RateLimit) * time.Millisecond)
    }
    
    var resp *http.Response
    var err error
    
    maxRetries := config.Retry
    if maxRetries < 1 {
        maxRetries = 1
    }
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        resp, err = client.Do(req)
        if err == nil {
            return resp, nil
        }
        
        // Don't retry on TLS cancellation errors (proxy interception)
        if config.Proxy != "" && isTLSCanceledError(err) {
            return nil, err
        }
        
        // Retry with exponential backoff
        if attempt < maxRetries-1 {
            backoff := time.Duration(attempt+1) * time.Second
            time.Sleep(backoff)
        }
    }
    
    return nil, err
}

// searchForSensitiveDataWithConfig enhanced version with all new features
func searchForSensitiveDataWithConfig(urlStr string, config *Config) (string, map[string][]string) {
    client := createHTTPClientWithConfig(config)
    var sensitiveData map[string][]string

    if strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://") {
        req, err := http.NewRequest("GET", urlStr, nil)
        if err != nil {
            if config.Verbose {
                fmt.Printf("Failed to create request for URL %s: %v\n", urlStr, err)
            }
            return urlStr, nil
        }

        // Apply custom headers
        for _, header := range config.Headers {
            parts := strings.SplitN(header, ":", 2)
            if len(parts) == 2 {
                key := strings.TrimSpace(parts[0])
                value := strings.TrimSpace(parts[1])
                req.Header.Set(key, value)
                if config.Verbose {
                    fmt.Printf("[%sINFO%s] Added header: %s: %s\n", colors["CYAN"], colors["NC"], key, value)
                }
            } else if config.Verbose {
                fmt.Printf("[%sWARN%s] Invalid header format (expected 'Key: Value'): %s\n", colors["YELLOW"], colors["NC"], header)
            }
        }

        // Apply custom User-Agent (randomly select from list if available)
        if len(config.UserAgents) > 0 {
            // Randomly select a user agent from the list for each request
            rand.Seed(time.Now().UnixNano() + int64(len(req.URL.String())))
            selectedUA := config.UserAgents[rand.Intn(len(config.UserAgents))]
            req.Header.Set("User-Agent", selectedUA)
        } else if config.UserAgent != "" {
            req.Header.Set("User-Agent", config.UserAgent)
        }

        // Apply cookies
        if config.Cookies != "" {
            req.Header.Set("Cookie", config.Cookies)
        }

        resp, err := makeRequestWithRetry(client, req, config)
        if err != nil {
            // Don't show errors in quiet mode
            if !config.Quiet {
                // Always show errors in verbose mode, or if not using proxy
                if config.Verbose || config.Proxy == "" {
                    if !isTLSCanceledError(err) {
                        fmt.Printf("[%sERROR%s] Request failed for %s: %v\n", colors["RED"], colors["NC"], urlStr, err)
                    } else if config.Verbose {
                        fmt.Printf("[%sINFO%s] TLS connection canceled (proxy interception): %s\n", colors["YELLOW"], colors["NC"], urlStr)
                    }
                } else if !isTLSCanceledError(err) {
                    // Show non-TLS errors even without verbose mode
                    fmt.Printf("[%sERROR%s] Request failed for %s: %v\n", colors["RED"], colors["NC"], urlStr, err)
                }
            }
            return urlStr, nil
        }
        
        if config.Verbose {
            fmt.Printf("[%sINFO%s] Successfully fetched %s (Status: %d)\n", colors["GREEN"], colors["NC"], urlStr, resp.StatusCode)
        }
        defer resp.Body.Close()

        // Filter: Only process JavaScript content
        if !shouldProcessResponse(resp, urlStr, config) {
            return urlStr, nil
        }

        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
            if config.Proxy == "" || !isTLSCanceledError(err) {
                if len(body) == 0 && config.Verbose {
                    fmt.Printf("Error reading response body: %v\n", err)
                }
            }
            if len(body) == 0 {
                return urlStr, nil
            }
        }

        // Process JS analysis features
        if len(body) > 0 {
            processedBody := processJSAnalysis(body, config)
            sensitiveData = reportMatchesWithConfig(urlStr, processedBody, config)
        } else {
            sensitiveData = make(map[string][]string)
        }
    } else {
        body, err := ioutil.ReadFile(urlStr)
        if err != nil {
            if config.Verbose {
                fmt.Printf("Error reading local file %s: %v\n", urlStr, err)
            }
            return urlStr, nil
        }

        processedBody := processJSAnalysis(body, config)
        sensitiveData = reportMatchesWithConfig(urlStr, processedBody, config)
    }

    return urlStr, sensitiveData
}

// processJSAnalysis applies JS analysis features (deobfuscation, sourcemap, etc.)
func processJSAnalysis(body []byte, config *Config) []byte {
    content := string(body)
    
    // Deobfuscation (basic - can be enhanced)
    if config.Deobfuscate {
        content = basicDeobfuscate(content)
    }
    
    // Source map parsing (placeholder - would need actual sourcemap library)
    if config.SourceMap {
        // Extract sourcemap URL and parse if available
        content = extractSourceMap(content)
    }
    
    // Eval analysis - extract strings from eval() calls
    if config.Eval {
        content = extractEvalContent(content)
    }
    
    // Obfuscation detection
    if config.ObfsDetect {
        if isObfuscated(content) && config.Verbose {
            fmt.Printf("[%sOBFS%s] Obfuscated code detected\n", colors["YELLOW"], colors["NC"])
        }
    }
    
    return []byte(content)
}

// Basic deobfuscation helpers
func basicDeobfuscate(content string) string {
    // Remove common obfuscation patterns
    // This is a basic implementation - can be enhanced
    content = strings.ReplaceAll(content, "\\x", "")
    content = strings.ReplaceAll(content, "\\u", "")
    return content
}

func extractSourceMap(content string) string {
    // Extract sourcemap references
    re := regexp.MustCompile(`//# sourceMappingURL=([^\s]+)`)
    matches := re.FindAllStringSubmatch(content, -1)
    if len(matches) > 0 {
        // Would fetch and parse sourcemap here
    }
    return content
}

func extractEvalContent(content string) string {
    // Extract content from eval() calls for analysis
    re := regexp.MustCompile(`eval\s*\(\s*["']([^"']+)["']`)
    matches := re.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            content += "\n// EVAL: " + match[1]
        }
    }
    return content
}

func isObfuscated(content string) bool {
    // Simple heuristics for obfuscation detection
    if len(content) > 1000 && strings.Count(content, "\\x") > 50 {
        return true
    }
    if strings.Contains(content, "eval(") && strings.Count(content, "String.fromCharCode") > 10 {
        return true
    }
    return false
}

// extractURLParamsWithBaseURLs - Advanced extraction of GET parameters with their base URLs
func extractURLParamsWithBaseURLs(content, source string) []string {
    var resultURLs []string
    seenURLs := make(map[string]bool)
    
    // Extract base URL from source if it's a URL
    var baseURL string
    var sourceDomain string // Store the main domain for fallback
    if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
        parsedURL, err := url.Parse(source)
        if err == nil {
            baseURL = parsedURL.Scheme + "://" + parsedURL.Host
            sourceDomain = parsedURL.Scheme + "://" + parsedURL.Host
        }
    }
    
    // Pattern 1: URLSearchParams.get() - Extract parameter names
    // Match: urlParams.get('param_name') or searchParams.get("param_name")
    urlParamsGetPattern := regexp.MustCompile(`(?:urlParams|searchParams|params|urlSearchParams|queryParams|locationParams)\.get\(["']([a-zA-Z0-9_\-\[\]]+)["']\)`)
    matches := urlParamsGetPattern.FindAllStringSubmatch(content, -1)
    paramSet := make(map[string]bool)
    for _, match := range matches {
        if len(match) > 1 {
            param := strings.TrimSpace(match[1])
            if len(param) > 0 && len(param) < 100 {
                paramSet[param] = true
            }
        }
    }
    
    // Pattern 2: URLSearchParams.getAll() - Extract parameter names
    urlParamsGetAllPattern := regexp.MustCompile(`(?:urlParams|searchParams|params|urlSearchParams|queryParams)\.getAll\(["']([a-zA-Z0-9_\-\[\]]+)["']\)`)
    matches = urlParamsGetAllPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            param := strings.TrimSpace(match[1])
            if len(param) > 0 && len(param) < 100 {
                paramSet[param] = true
            }
        }
    }
    
    // Pattern 3: URL.searchParams.get() - Extract parameter names
    urlSearchParamsPattern := regexp.MustCompile(`(?:new\s+URL\([^)]+\)|currentUrl|url|apiUrl|baseUrl)\.searchParams\.get\(["']([a-zA-Z0-9_\-\[\]]+)["']\)`)
    matches = urlSearchParamsPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            param := strings.TrimSpace(match[1])
            if len(param) > 0 && len(param) < 100 {
                paramSet[param] = true
            }
        }
    }
    
    // Pattern 4: Manual string parsing - Extract from split('&') patterns
    manualParsePattern := regexp.MustCompile(`pair\[0\]\s*===\s*["']([a-zA-Z0-9_\-]+)["']`)
    matches = manualParsePattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            param := strings.TrimSpace(match[1])
            if len(param) > 0 && len(param) < 100 {
                paramSet[param] = true
            }
        }
    }
    
    // Pattern 5: Custom getParam() function calls
    customGetParamPattern := regexp.MustCompile(`getParam\(["']([a-zA-Z0-9_\-]+)["']\)`)
    matches = customGetParamPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            param := strings.TrimSpace(match[1])
            if len(param) > 0 && len(param) < 100 {
                paramSet[param] = true
            }
        }
    }
    
    // Pattern 5b: URLSearchParams.has() - parameters that are checked
    urlParamsHasPattern := regexp.MustCompile(`(?:urlParams|searchParams|params|urlSearchParams|queryParams)\.has\(["']([a-zA-Z0-9_\-\[\]]+)["']\)`)
    matches = urlParamsHasPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            param := strings.TrimSpace(match[1])
            if len(param) > 0 && len(param) < 100 {
                paramSet[param] = true
            }
        }
    }
    
    // Pattern 5c: Direct URL parameter extraction from query strings in code
    directQueryPattern := regexp.MustCompile(`["']([a-zA-Z0-9_\-]+)["']\s*[:=]\s*(?:urlParams|searchParams|params)\.get\(`)
    matches = directQueryPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            param := strings.TrimSpace(match[1])
            if len(param) > 0 && len(param) < 100 {
                paramSet[param] = true
            }
        }
    }
    
    // Pattern 6: Fetch/Axios with URLSearchParams in URL (template literals and strings)
    fetchWithParamsPattern := regexp.MustCompile(`fetch\(["'` + "`" + `]([^"'` + "`" + `]+)\?[^"'` + "`" + `]*["'` + "`" + `]`)
    matches = fetchWithParamsPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            fullURL := match[1]
            // Extract base URL
            if strings.HasPrefix(fullURL, "http") {
                parsedURL, err := url.Parse(fullURL)
                if err == nil {
                    base := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
                    // Extract params from query string
                    if parsedURL.RawQuery != "" {
                        queryParams, _ := url.ParseQuery(parsedURL.RawQuery)
                        var params []string
                        for key := range queryParams {
                            if len(key) > 0 && len(key) < 100 {
                                params = append(params, key)
                            }
                        }
                        if len(params) > 0 {
                            // Check if URL is from same base domain
                            urlDomain := extractBaseDomain(parsedURL.Host)
                            sourceBaseDomain := extractBaseDomain(extractDomain(source))
                            if sourceBaseDomain == "" || urlDomain == sourceBaseDomain {
                                sort.Strings(params)
                                queryStr := strings.Join(params, "=&") + "="
                                resultURL := base + "?" + queryStr
                                if !seenURLs[resultURL] {
                                    seenURLs[resultURL] = true
                                    resultURLs = append(resultURLs, resultURL)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Pattern 6b: Fetch with template literals containing parameters
    fetchTemplatePattern := regexp.MustCompile(`fetch\(` + "`" + `([^` + "`" + `]+)\$\{[^}]+\}[^` + "`" + `]*` + "`" + `\)`)
    matches = fetchTemplatePattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            urlPart := match[1]
            // Extract base URL from template
            if strings.Contains(urlPart, "?") {
                parts := strings.Split(urlPart, "?")
                if len(parts) > 0 {
                    basePart := parts[0]
                    if strings.HasPrefix(basePart, "http") {
                        parsedURL, err := url.Parse(basePart)
                        if err == nil {
                            base := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
                            // Extract parameter names from template (look for ${var} patterns)
                            paramVarPattern := regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)
                            varMatches := paramVarPattern.FindAllStringSubmatch(match[0], -1)
                            var params []string
                            for _, vm := range varMatches {
                                if len(vm) > 1 {
                                    // Try to find what this variable represents (might be a param name)
                                    varName := vm[1]
                                    // Look for this variable being assigned from urlParams.get()
                                    varPattern := regexp.MustCompile(varName + `\s*=\s*(?:urlParams|searchParams|params)\.get\(["']([^"']+)["']\)`)
                                    varAssignMatches := varPattern.FindAllStringSubmatch(content, -1)
                                    if len(varAssignMatches) > 0 {
                                        paramName := varAssignMatches[0][1]
                                        params = append(params, paramName)
                                    }
                                }
                            }
                            // Also extract from query string part if present
                            if len(parts) > 1 {
                                queryPart := parts[1]
                                queryParamPattern := regexp.MustCompile(`([a-zA-Z0-9_\-]+)=`)
                                queryMatches := queryParamPattern.FindAllStringSubmatch(queryPart, -1)
                                for _, qm := range queryMatches {
                                    if len(qm) > 1 {
                                        params = append(params, qm[1])
                                    }
                                }
                            }
                            if len(params) > 0 {
                                // Check if URL is from same base domain
                                urlDomain := extractBaseDomain(parsedURL.Host)
                                sourceBaseDomain := extractBaseDomain(extractDomain(source))
                                if sourceBaseDomain == "" || urlDomain == sourceBaseDomain {
                                    sort.Strings(params)
                                    queryStr := strings.Join(params, "=&") + "="
                                    resultURL := base + "?" + queryStr
                                    if !seenURLs[resultURL] {
                                        seenURLs[resultURL] = true
                                        resultURLs = append(resultURLs, resultURL)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Pattern 7: Axios params object
    axiosParamsPattern := regexp.MustCompile(`axios\.(?:get|post|put|delete|patch)\(["']([^"']+)["'][^)]*params\s*:\s*\{([^}]+)\}`)
    matches = axiosParamsPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 2 {
            apiURL := match[1]
            paramsStr := match[2]
            // Extract parameter names from params object
            paramNamePattern := regexp.MustCompile(`([a-zA-Z0-9_\-]+)\s*:`)
            paramMatches := paramNamePattern.FindAllStringSubmatch(paramsStr, -1)
            var params []string
            for _, pm := range paramMatches {
                if len(pm) > 1 {
                    param := strings.TrimSpace(pm[1])
                    if len(param) > 0 && len(param) < 100 {
                        params = append(params, param)
                    }
                }
            }
            if len(params) > 0 {
                // Build full URL
                if !strings.HasPrefix(apiURL, "http") && baseURL != "" {
                    apiURL = baseURL + apiURL
                } else if !strings.HasPrefix(apiURL, "http") {
                    // Use source domain if available, otherwise skip
                    if sourceDomain != "" {
                        apiURL = sourceDomain + apiURL
                    } else {
                        continue // Skip if no domain available
                    }
                }
                // Check if URL is from same base domain
                parsedAPIURL, err := url.Parse(apiURL)
                if err == nil {
                    urlDomain := extractBaseDomain(parsedAPIURL.Host)
                    sourceBaseDomain := extractBaseDomain(extractDomain(source))
                    if sourceBaseDomain == "" || urlDomain == sourceBaseDomain {
                        sort.Strings(params)
                        queryStr := strings.Join(params, "=&") + "="
                        // Check if apiURL already has a query string
                        separator := "?"
                        if strings.Contains(apiURL, "?") {
                            separator = "&"
                        }
                        resultURL := apiURL + separator + queryStr
                        if !seenURLs[resultURL] {
                            seenURLs[resultURL] = true
                            resultURLs = append(resultURLs, resultURL)
                        }
                    }
                }
            }
        }
    }
    
    // Pattern 8: URLSearchParams constructor with object
    urlSearchParamsObjPattern := regexp.MustCompile(`new\s+URLSearchParams\([^)]*\{([^}]+)\}[^)]*\)`)
    matches = urlSearchParamsObjPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            paramsStr := match[1]
            paramNamePattern := regexp.MustCompile(`([a-zA-Z0-9_\-]+)\s*:`)
            paramMatches := paramNamePattern.FindAllStringSubmatch(paramsStr, -1)
            var params []string
            for _, pm := range paramMatches {
                if len(pm) > 1 {
                    param := strings.TrimSpace(pm[1])
                    if len(param) > 0 && len(param) < 100 {
                        params = append(params, param)
                    }
                }
            }
            if len(params) > 0 {
                // Find associated URL in nearby context
                contextStart := strings.LastIndex(content[:strings.Index(content, match[0])], "fetch(")
                contextStart2 := strings.LastIndex(content[:strings.Index(content, match[0])], "axios.")
                if contextStart2 > contextStart {
                    contextStart = contextStart2
                }
                if contextStart > 0 {
                    // Extract URL from context
                    urlPattern := regexp.MustCompile(`["']([^"']+)["']`)
                    context := content[contextStart:strings.Index(content, match[0])]
                    urlMatches := urlPattern.FindAllStringSubmatch(context, -1)
                    if len(urlMatches) > 0 {
                        apiURL := urlMatches[0][1]
                        if !strings.HasPrefix(apiURL, "http") && baseURL != "" {
                            apiURL = baseURL + apiURL
                        } else if !strings.HasPrefix(apiURL, "http") {
                            // Use source domain if available, otherwise skip
                            if sourceDomain != "" {
                                apiURL = sourceDomain + apiURL
                            } else {
                                continue // Skip if no domain available
                            }
                        }
                        // Check if URL is from same base domain
                        parsedAPIURL, err := url.Parse(apiURL)
                        if err == nil {
                            urlDomain := extractBaseDomain(parsedAPIURL.Host)
                            sourceBaseDomain := extractBaseDomain(extractDomain(source))
                            if sourceBaseDomain == "" || urlDomain == sourceBaseDomain {
                                sort.Strings(params)
                                queryStr := strings.Join(params, "=&") + "="
                                // Check if apiURL already has a query string
                                separator := "?"
                                if strings.Contains(apiURL, "?") {
                                    separator = "&"
                                }
                                resultURL := apiURL + separator + queryStr
                                if !seenURLs[resultURL] {
                                    seenURLs[resultURL] = true
                                    resultURLs = append(resultURLs, resultURL)
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Pattern 9: Direct URL with query parameters in strings
    directURLPattern := regexp.MustCompile(`["'](https?://[^"']+\?[^"']+)["']`)
    matches = directURLPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            fullURL := match[1]
            parsedURL, err := url.Parse(fullURL)
            if err == nil {
                base := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
                if parsedURL.RawQuery != "" {
                    queryParams, _ := url.ParseQuery(parsedURL.RawQuery)
                    var params []string
                    for key := range queryParams {
                        if len(key) > 0 && len(key) < 100 {
                            params = append(params, key)
                        }
                    }
                    if len(params) > 0 {
                        // Check if URL is from same base domain
                        urlDomain := extractBaseDomain(parsedURL.Host)
                        sourceBaseDomain := extractBaseDomain(extractDomain(source))
                        if sourceBaseDomain == "" || urlDomain == sourceBaseDomain {
                            sort.Strings(params)
                            queryStr := strings.Join(params, "=&") + "="
                            resultURL := base + "?" + queryStr
                            if !seenURLs[resultURL] {
                                seenURLs[resultURL] = true
                                resultURLs = append(resultURLs, resultURL)
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Pattern 10: XHR.open() with parameters
    xhrPattern := regexp.MustCompile(`\.open\(["'](?:GET|POST|PUT|DELETE|PATCH)["']\s*,\s*["']([^"']+\?[^"']+)["']`)
    matches = xhrPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            fullURL := match[1]
            parsedURL, err := url.Parse(fullURL)
            if err == nil {
                base := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
                if parsedURL.RawQuery != "" {
                    queryParams, _ := url.ParseQuery(parsedURL.RawQuery)
                    var params []string
                    for key := range queryParams {
                        if len(key) > 0 && len(key) < 100 {
                            params = append(params, key)
                        }
                    }
                    if len(params) > 0 {
                        // Check if URL is from same base domain
                        urlDomain := extractBaseDomain(parsedURL.Host)
                        sourceBaseDomain := extractBaseDomain(extractDomain(source))
                        if sourceBaseDomain == "" || urlDomain == sourceBaseDomain {
                            sort.Strings(params)
                            queryStr := strings.Join(params, "=&") + "="
                            resultURL := base + "?" + queryStr
                            if !seenURLs[resultURL] {
                                seenURLs[resultURL] = true
                                resultURLs = append(resultURLs, resultURL)
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Pattern 11: Template literals with parameters
    templateLiteralPattern := regexp.MustCompile(`\$\{([^}]+)\?[^}]*\}`)
    matches = templateLiteralPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            // This is complex, skip for now or extract base URL
        }
    }
    
    // Always create URLs from all collected parameters (even if some URLs were found from fetch/axios)
    if len(paramSet) > 0 {
        // Group parameters by context - find parameters used together in same function
        paramGroups := groupParamsByContext(content, paramSet)
        
        // Try to find base URLs in the content
        baseURLPatterns := []*regexp.Regexp{
            regexp.MustCompile(`["'](https?://[^"']+/[^"']*)["']`),
            regexp.MustCompile(`baseURL\s*[:=]\s*["']([^"']+)["']`),
            regexp.MustCompile(`apiBase\s*[:=]\s*["']([^"']+)["']`),
            regexp.MustCompile(`API_URL\s*[:=]\s*["']([^"']+)["']`),
            regexp.MustCompile(`endpointBase\s*[:=]\s*["']([^"']+)["']`),
        }
        
        var foundBaseURL string
        for _, pattern := range baseURLPatterns {
            urlMatches := pattern.FindAllStringSubmatch(content, -1)
            if len(urlMatches) > 0 {
                foundBaseURL = urlMatches[0][1]
                // Remove query string if present
                if idx := strings.Index(foundBaseURL, "?"); idx != -1 {
                    foundBaseURL = foundBaseURL[:idx]
                }
                if !strings.HasSuffix(foundBaseURL, "/") {
                    foundBaseURL = strings.TrimRight(foundBaseURL, "/")
                }
                break
            }
        }
        
        if foundBaseURL == "" {
            if baseURL != "" {
                // Use the source domain root path when full path is unknown
                foundBaseURL = baseURL
            } else if sourceDomain != "" {
                // Use source domain root when no base URL found
                foundBaseURL = sourceDomain
            } else {
                // Skip if no domain available
                return resultURLs
            }
        }
        
        // Create URLs for each parameter group
        for _, group := range paramGroups {
            if len(group) > 0 {
                sort.Strings(group)
                // Remove duplicates from group
                uniqueGroup := []string{}
                seenInGroup := make(map[string]bool)
                for _, p := range group {
                    if !seenInGroup[p] {
                        seenInGroup[p] = true
                        uniqueGroup = append(uniqueGroup, p)
                    }
                }
                
                if len(uniqueGroup) == 1 {
                    // Single parameter - use root path
                    singleURL := foundBaseURL + "/?" + uniqueGroup[0] + "="
                    if !seenURLs[singleURL] {
                        seenURLs[singleURL] = true
                        resultURLs = append(resultURLs, singleURL)
                    }
                } else if len(uniqueGroup) > 1 {
                    // Multiple parameters - join with &, use root path
                    queryStr := strings.Join(uniqueGroup, "=&") + "="
                    resultURL := foundBaseURL + "/?" + queryStr
                    if !seenURLs[resultURL] {
                        seenURLs[resultURL] = true
                        resultURLs = append(resultURLs, resultURL)
                    }
                }
            }
        }
        
        // Also create individual URLs for each parameter (if not already created)
        paramsList := make([]string, 0, len(paramSet))
        for param := range paramSet {
            paramsList = append(paramsList, param)
        }
        sort.Strings(paramsList)
        for _, param := range paramsList {
            // Use root path when full path is unknown
            singleURL := foundBaseURL + "/?" + param + "="
            if !seenURLs[singleURL] {
                seenURLs[singleURL] = true
                resultURLs = append(resultURLs, singleURL)
            }
        }
    }
    
    // Filter URLs by domain - only include URLs from the same base domain as source
    if sourceDomain != "" {
        sourceBaseDomain := extractBaseDomain(extractDomain(source))
        if sourceBaseDomain != "" {
            filteredURLs := []string{}
            for _, resultURL := range resultURLs {
                // Extract domain from result URL
                urlDomain := extractDomain(resultURL)
                if urlDomain != "" {
                    urlBaseDomain := extractBaseDomain(urlDomain)
                    // Only include if it's from the same base domain
                    if urlBaseDomain == sourceBaseDomain {
                        filteredURLs = append(filteredURLs, resultURL)
                    }
                } else {
                    // If we can't extract domain (relative URL), include it (it's from source domain)
                    filteredURLs = append(filteredURLs, resultURL)
                }
            }
            return filteredURLs
        }
    }
    
    return resultURLs
}

// groupParamsByContext groups parameters that are used together in the same function/context
func groupParamsByContext(content string, paramSet map[string]bool) [][]string {
    var groups [][]string
    usedParams := make(map[string]bool)
    
    // Find function blocks and group parameters within them
    // Look for common patterns where multiple params are used together
    
    // Pattern: Multiple .get() calls in sequence (likely same function)
    urlParamsPattern := regexp.MustCompile(`(?:urlParams|searchParams|params|urlSearchParams|queryParams)\.get\(["']([a-zA-Z0-9_\-\[\]]+)["']\)`)
    allMatches := urlParamsPattern.FindAllStringSubmatchIndex(content, -1)
    
    // Group consecutive parameter extractions (within 200 chars)
    var currentGroup []string
    lastPos := -1
    
    for _, match := range allMatches {
        if len(match) >= 4 {
            paramName := content[match[2]:match[3]]
            currentPos := match[0]
            
            if paramSet[paramName] && !usedParams[paramName] {
                if lastPos == -1 || (currentPos - lastPos) < 200 {
                    // Same context
                    currentGroup = append(currentGroup, paramName)
                    usedParams[paramName] = true
                } else {
                    // New context
                    if len(currentGroup) > 0 {
                        groups = append(groups, currentGroup)
                    }
                    currentGroup = []string{paramName}
                    usedParams[paramName] = true
                }
                lastPos = currentPos
            }
        }
    }
    
    if len(currentGroup) > 0 {
        groups = append(groups, currentGroup)
    }
    
    // Also look for URLSearchParams object creation with multiple params
    urlSearchParamsObjPattern := regexp.MustCompile(`new\s+URLSearchParams\([^)]*\{([^}]+)\}`)
    matches := urlSearchParamsObjPattern.FindAllStringSubmatch(content, -1)
    for _, match := range matches {
        if len(match) > 1 {
            paramsStr := match[1]
            paramNamePattern := regexp.MustCompile(`([a-zA-Z0-9_\-]+)\s*:`)
            paramMatches := paramNamePattern.FindAllStringSubmatch(paramsStr, -1)
            var group []string
            for _, pm := range paramMatches {
                if len(pm) > 1 {
                    param := strings.TrimSpace(pm[1])
                    if paramSet[param] && !usedParams[param] {
                        group = append(group, param)
                        usedParams[param] = true
                    }
                }
            }
            if len(group) > 0 {
                groups = append(groups, group)
            }
        }
    }
    
    return groups
}

// cleanURL removes trailing punctuation and invalid characters from URLs
func cleanURL(urlStr string) string {
    // Remove trailing punctuation: , ; \ ) | etc.
    urlStr = strings.TrimRight(urlStr, ",;\\|)")
    
    // Remove any trailing quotes
    urlStr = strings.Trim(urlStr, `"'`)
    
    // Remove any trailing special characters that are not valid in URLs
    urlStr = strings.TrimRight(urlStr, " \t\n\r")
    
    return urlStr
}

// isValidURL checks if a URL is valid (proper format, not malformed)
func isValidURL(urlStr string) bool {
    // Parse the URL
    parsedURL, err := url.Parse(urlStr)
    if err != nil {
        return false
    }
    
    // Must have a valid scheme
    if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
        return false
    }
    
    // Must have a host
    if parsedURL.Host == "" {
        return false
    }
    
    // Check for malformed port (e.g., :80x)
    if strings.Contains(parsedURL.Host, ":") {
        hostParts := strings.Split(parsedURL.Host, ":")
        if len(hostParts) == 2 {
            // Port must be numeric
            port := hostParts[1]
            for _, char := range port {
                if char < '0' || char > '9' {
                    return false // Invalid port (contains non-numeric characters)
                }
            }
        }
    }
    
    return true
}

// isPlaceholderURL checks if a URL is a placeholder/template (not a real URL)
func isPlaceholderURL(urlStr string) bool {
    urlLower := strings.ToLower(urlStr)
    
    // Common placeholder patterns
    placeholders := []string{
        "servername", "hostname", "domain.com", "example.com", "example.org",
        "yourserver", "yourdomain", "localhost", "127.0.0.1", "0.0.0.0",
        "server.com", "host.com", "domain.org", "site.com", "mydomain.com",
        ":port/", "accounturl", "username", "password",
    }
    
    for _, placeholder := range placeholders {
        if strings.Contains(urlLower, placeholder) {
            return true
        }
    }
    
    // Check for template variables like ${variable} or {variable} or %variable%
    if strings.Contains(urlStr, "${") || strings.Contains(urlStr, "%{") || 
       strings.Contains(urlStr, "{{") || strings.Contains(urlStr, "<%") {
        return true
    }
    
    return false
}

// isURLInComment checks if a URL appears to be in a JavaScript comment
func isURLInComment(context, match string) bool {
    // Find the position of the match in the context
    matchPos := strings.Index(context, match)
    if matchPos == -1 {
        return false
    }
    
    // Look backwards from the match to check for comment markers
    beforeMatch := context[:matchPos]
    
    // Check for single-line comment (//)
    // Find the last newline before the match
    lastNewline := strings.LastIndex(beforeMatch, "\n")
    if lastNewline != -1 {
        lineBeforeMatch := beforeMatch[lastNewline+1:]
        // If there's a // before the match on the same line, it's in a comment
        if strings.Contains(lineBeforeMatch, "//") {
            return true
        }
    } else {
        // No newline found, check entire beforeMatch
        if strings.Contains(beforeMatch, "//") {
            return true
        }
    }
    
    // Check for multi-line comment (/* ... */)
    // Find the last /* and */ before the match
    lastCommentStart := strings.LastIndex(beforeMatch, "/*")
    lastCommentEnd := strings.LastIndex(beforeMatch, "*/")
    
    // If /* is found and there's no */ after it (or */ comes before /*), we're in a comment
    if lastCommentStart != -1 {
        if lastCommentEnd == -1 || lastCommentEnd < lastCommentStart {
            // We're inside a multi-line comment
            return true
        }
    }
    
    return false
}

// isMatchInBase64DataURI checks if a match is inside a base64 data URI (e.g., data:image/png;base64,...)
func isMatchInBase64DataURI(context, match string) bool {
    // Find the position of the match in the context
    matchPos := strings.Index(context, match)
    if matchPos == -1 {
        return false
    }
    
    // Look backwards from the match position to find "base64,"
    // This is more reliable than looking for the full data URI pattern
    searchStart := matchPos - 300 // Look back up to 300 characters
    if searchStart < 0 {
        searchStart = 0
    }
    searchContext := context[searchStart:matchPos]
    
    // Find the last occurrence of "base64," before the match
    base64Pos := strings.LastIndex(searchContext, "base64,")
    if base64Pos == -1 {
        return false
    }
    
    // Check if there's a data URI pattern before "base64,"
    // Pattern: data:image/[type];base64, or data:[type];base64,
    dataURIPattern := regexp.MustCompile(`data:(?:image/[a-zA-Z0-9+\-]+|application/[a-zA-Z0-9+\-]+|text/[a-zA-Z0-9+\-]+);base64,`)
    
    // Get the text before "base64," to check for data URI pattern
    beforeBase64 := searchContext[:base64Pos+6] // Include "base64," in the check
    
    // Check if we have a valid data URI pattern ending with "base64,"
    // Look backwards from "base64," to find "data:"
    dataPos := strings.LastIndex(beforeBase64, "data:")
    if dataPos == -1 {
        return false
    }
    
    // Extract the potential data URI
    potentialDataURI := searchContext[dataPos:base64Pos+6]
    
    // Check if it matches the data URI pattern
    if dataURIPattern.MatchString(potentialDataURI) {
        // The match is after "base64,", so it's part of base64 encoded data
        return true
    }
    
    return false
}

// isLikelyBase64MediaData checks if a match looks like base64-encoded media content
func isLikelyBase64MediaData(context, match string) bool {
    // Check if the match itself looks like base64 data
    if !looksLikeBase64(match) {
        return false
    }
    
    // Find the position of the match in the context
    matchPos := strings.Index(context, match)
    if matchPos == -1 {
        return false
    }
    
    // Get surrounding context for analysis
    contextStart := matchPos - 200
    if contextStart < 0 {
        contextStart = 0
    }
    contextEnd := matchPos + len(match) + 200
    if contextEnd > len(context) {
        contextEnd = len(context)
    }
    surroundingContext := context[contextStart:contextEnd]
    
    // Check for media-related indicators in surrounding context
    mediaIndicators := []string{
        "data:image", "data:video", "data:audio",
        "base64,", "data:application/octet-stream",
        "png", "jpg", "jpeg", "gif", "webp", "svg",
        "mp4", "webm", "ogg", "wav", "mp3",
        "font", "woff", "woff2", "ttf", "otf",
        "modernizr", "polyfill", "encoded", "binary",
    }
    
    lowerContext := strings.ToLower(surroundingContext)
    for _, indicator := range mediaIndicators {
        if strings.Contains(lowerContext, indicator) {
            return true
        }
    }
    
    // Check for long base64 strings (likely media content)
    if len(match) > 100 && hasHighBase64Entropy(match) {
        return true
    }
    
    // Check if it's part of a larger base64 string
    if isPartOfLargerBase64String(context, matchPos, len(match)) {
        return true
    }
    
    return false
}

// looksLikeBase64 checks if a string looks like base64 encoded data
func looksLikeBase64(s string) bool {
    if len(s) < 16 { // Too short to be meaningful base64
        return false
    }
    
    // Base64 uses A-Z, a-z, 0-9, +, /, and = for padding
    validChars := 0
    for _, r := range s {
        if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || 
           (r >= '0' && r <= '9') || r == '+' || r == '/' || r == '=' {
            validChars++
        }
    }
    
    // Should be mostly valid base64 characters
    ratio := float64(validChars) / float64(len(s))
    return ratio > 0.95
}

// hasHighBase64Entropy checks if the string has high entropy typical of encoded data
func hasHighBase64Entropy(s string) bool {
    if len(s) < 32 {
        return false
    }
    
    // Count character frequency
    charCount := make(map[rune]int)
    for _, r := range s {
        charCount[r]++
    }
    
    // Calculate entropy
    entropy := 0.0
    length := float64(len(s))
    for _, count := range charCount {
        if count > 0 {
            p := float64(count) / length
            entropy -= p * math.Log2(p)
        }
    }
    
    // Base64 encoded data typically has entropy > 4.5
    // Media files when base64 encoded usually have high entropy
    return entropy > 4.5
}

// isPartOfLargerBase64String checks if the match is part of a larger base64 encoded string
func isPartOfLargerBase64String(context string, matchPos, matchLen int) bool {
    // Look at characters before and after the match
    expandedStart := matchPos - 50
    if expandedStart < 0 {
        expandedStart = 0
    }
    expandedEnd := matchPos + matchLen + 50
    if expandedEnd > len(context) {
        expandedEnd = len(context)
    }
    
    expandedString := context[expandedStart:expandedEnd]
    
    // Check if the expanded string looks like base64
    if len(expandedString) > len(context[matchPos:matchPos+matchLen])*2 && looksLikeBase64(expandedString) {
        return true
    }
    
    return false
}

// extractDomain extracts the domain from a URL string
func extractDomain(urlStr string) string {
    if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
        return ""
    }
    
    parsedURL, err := url.Parse(urlStr)
    if err != nil {
        return ""
    }
    
    host := parsedURL.Host
    // Remove port if present
    if idx := strings.Index(host, ":"); idx != -1 {
        host = host[:idx]
    }
    
    return host
}

// extractBaseDomain extracts the base domain (e.g., "target.com" from "assest.target.com")
func extractBaseDomain(domain string) string {
    if domain == "" {
        return ""
    }
    
    // Handle IP addresses - return as is
    if net.ParseIP(domain) != nil {
        return domain
    }
    
    // Handle localhost and single-label domains
    if !strings.Contains(domain, ".") {
        return domain
    }
    
    parts := strings.Split(domain, ".")
    if len(parts) < 2 {
        return domain
    }
    
    // For most cases, base domain is last 2 parts (e.g., target.com)
    // But handle special cases like .co.uk, .com.au, etc.
    // For simplicity, we'll use last 2 parts for now
    // This works for most common cases: target.com, example.org, etc.
    if len(parts) >= 2 {
        return parts[len(parts)-2] + "." + parts[len(parts)-1]
    }
    
    return domain
}

// isSameBaseDomain checks if two domains share the same base domain (handles subdomains)
func isSameBaseDomain(domain1, domain2 string) bool {
    if domain1 == "" || domain2 == "" {
        return false
    }
    
    base1 := extractBaseDomain(domain1)
    base2 := extractBaseDomain(domain2)
    
    return base1 == base2 && base1 != ""
}

// isMatchInURL checks if a match appears to be part of a URL from a different domain
func isMatchInURL(context, match, sourceDomain string) bool {
    if sourceDomain == "" {
        return false // Can't compare if source is not a URL
    }
    
    sourceBaseDomain := extractBaseDomain(sourceDomain)
    if sourceBaseDomain == "" {
        return false
    }
    
    // Find all URLs in the context
    urlPattern := regexp.MustCompile(`https?://[^\s"'<>\)]+`)
    urls := urlPattern.FindAllString(context, -1)
    
    for _, urlStr := range urls {
        // Check if the match is contained within this URL
        if strings.Contains(urlStr, match) {
            urlDomain := extractDomain(urlStr)
            if urlDomain != "" {
                urlBaseDomain := extractBaseDomain(urlDomain)
                // If the URL's base domain doesn't match the source base domain, filter it out
                if urlBaseDomain != "" && urlBaseDomain != sourceBaseDomain {
                    return true // Match is part of a URL from a different base domain
                }
            }
        }
    }
    
    return false
}

// filterMatchesByDomain filters out matches that are from URLs on different domains
func filterMatchesByDomain(matches []string, sourceURL string) []string {
    sourceDomain := extractDomain(sourceURL)
    if sourceDomain == "" {
        return matches // Can't filter if source is not a URL
    }
    
    sourceBaseDomain := extractBaseDomain(sourceDomain)
    if sourceBaseDomain == "" {
        return matches
    }
    
    filtered := []string{}
    urlPattern := regexp.MustCompile(`https?://[^\s"'<>]+`)
    
    for _, match := range matches {
        shouldInclude := true
        
        // Check if match is a complete URL
        if urlPattern.MatchString(match) {
            matchDomain := extractDomain(match)
            if matchDomain != "" {
                matchBaseDomain := extractBaseDomain(matchDomain)
                // Only include if it's from the same base domain
                if matchBaseDomain != "" && matchBaseDomain != sourceBaseDomain {
                    shouldInclude = false // Different base domain URL
                }
            }
        } else {
            // Check if match appears to be part of a URL by looking for common URL indicators
            // This handles cases where the regex matched part of a URL string
            
            // Check for email addresses that might be part of URLs
            if strings.Contains(match, "@") {
                // Try to extract domain from email
                emailParts := strings.Split(match, "@")
                if len(emailParts) == 2 {
                    emailDomain := emailParts[1]
                    emailBaseDomain := extractBaseDomain(emailDomain)
                    // If email domain is from different base domain, filter it out
                    if emailBaseDomain != "" && emailBaseDomain != sourceBaseDomain {
                        shouldInclude = false
                    }
                }
            }
            
            // For other patterns (UUIDs, etc.), we rely on the context check in isMatchInURL
            // This secondary filter is mainly for additional safety
        }
        
        if shouldInclude {
            filtered = append(filtered, match)
        }
    }
    
    return filtered
}

// reportMatchesWithConfig enhanced reporting with all security analysis features
func reportMatchesWithConfig(source string, body []byte, config *Config) map[string][]string {
    matchesMap := make(map[string][]string)
    
    // Select patterns based on config
    patternsToUse := make(map[string]*regexp.Regexp)
    
    // Check if any Security Analysis flag is set
    hasSecurityFlag := config.Secrets || config.Tokens || config.GraphQL || 
                       config.Firebase || config.Links || config.Internal || 
                       config.Bypass || config.Params || config.ParamURLs
    
    // JS Analysis flags (-d, -m, -e, -z) are modifiers that work WITH pattern detection
    // They don't disable pattern detection, they just modify the JS before analysis
    // So if ONLY JS Analysis flags are set, we should still run ALL patterns (normal mode)
    
    // If NO Security Analysis flags are set, use all basic patterns (normal mode)
    // If Security Analysis flags ARE set, ONLY use those specific patterns
    if !hasSecurityFlag {
        // Normal mode: include all basic patterns
        // This includes when ONLY JS Analysis flags are set (like -d alone)
        for name, pattern := range regexPatterns {
            patternsToUse[name] = pattern
        }
    }
    
    // Add specialized patterns based on flags (ONLY if flag is set)
    if config.Secrets {
        // Add only secret-related patterns from regexPatterns
        secretPatterns := []string{
            // Original patterns
            "Google API", "Firebase", "Amazon Aws Access Key ID", "Amazon Mws Auth Token",
            "Facebook Access Token", "Authorization Basic", "Authorization Bearer", "Authorization Api",
            "Twilio Api Key", "Twilio Account Sid", "Twilio App Sid", "Paypal Braintre Access Token",
            "Square Oauth Secret", "Square Access Token", "Stripe Standard Api", "Stripe Restricted Api",
            "Authorization Github Token", "Github Access Token", "Rsa Private Key", "Ssh Dsa Private Key",
            "Ssh Dc Private Key", "Pgp Private Block", "Ssh Private Key", "Aws Api Key", "Slack Token",
            "Ssh Priv Key", "Heroku Api Key 2", "Heroku Api Key 3", "Slack Webhook Url", "Dropbox Access Token",
            "Salesforce Access Token", "Pem Private Key", "Google Cloud Sa Key", "Stripe Publishable Key",
            "Azure Storage Account Key", "Instagram Access Token", "Generic Api Key", "Generic Secret",

            // AI/LLM API Keys (CRITICAL)
            "OpenAI API Key", "OpenAI API Key Project", "OpenAI API Key Svc", "Anthropic API Key",
            "HuggingFace Token", "Cohere API Key", "Replicate API Token", "Google AI API Key",

            // AWS Secrets (CRITICAL)
            "AWS Secret Access Key", "AWS Session Token",

            // Database Connection Strings (CRITICAL)
            "MongoDB Connection String", "PostgreSQL Connection String", "MySQL Connection String",
            "Redis Connection String", "MSSQL Connection String", "Database URL Generic",

            // Azure Secrets (HIGH)
            "Azure Client Secret", "Azure Storage Connection", "Azure SAS Token", "Azure SQL Connection",

            // Cloud Providers (HIGH)
            "DigitalOcean Token", "DigitalOcean OAuth", "DigitalOcean Refresh", "Linode API Token",
            "Vultr API Key", "Hetzner API Token", "Oracle Cloud API Key", "IBM Cloud API Key",

            // CI/CD Tokens (HIGH - supply chain)
            "NPM Access Token", "PyPI API Token", "NuGet API Key", "RubyGems API Key",
            "CircleCI Token", "Travis CI Token", "Jenkins API Token", "Bitbucket App Password",
            "Codecov Token", "Vercel Token", "Netlify Token",

            // Infrastructure (CRITICAL)
            "Vault Token", "Kubernetes Token", "Docker Registry Password", "Terraform Cloud Token", "Pulumi Access Token",

            // Payment Processors (CRITICAL)
            "Adyen API Key", "Klarna API Key", "Razorpay Key", "Coinbase API Secret", "Binance API Secret",

            // Communication Services (HIGH)
            "Twilio Auth Token", "Pusher Secret", "Vonage API Secret", "Plivo Auth Token",
            "MessageBird API Key", "Intercom Access Token", "Zendesk API Token",

            // Search/Analytics (HIGH)
            "Algolia Admin API Key", "Elasticsearch API Key", "Mixpanel API Secret", "Amplitude API Key",

            // Monitoring/Logging (HIGH)
            "New Relic License Key", "New Relic API Key", "New Relic Insights Key",
            "Loggly Token", "Splunk HEC Token", "Sumo Logic Access Key", "Grafana API Key", "PagerDuty API Key",

            // Backend as a Service (HIGH)
            "Supabase Service Role Key", "Firebase Admin SDK Key", "Auth0 Client Secret", "Okta API Token Alt",

            // Cloud Storage (HIGH)
            "Cloudinary Secret", "Cloudinary URL", "Backblaze Application Key", "Wasabi Access Key",

            // Feature Flags
            "LaunchDarkly SDK Key", "LaunchDarkly API Key", "Split.io API Key", "Statsig Secret",

            // Version Control (HIGH)
            "GitLab Pipeline Token", "GitLab Runner Token", "GitHub App Private Key", "Bitbucket OAuth Secret",

            // CMS/Content
            "Contentful Management Token", "Contentful Delivery Token", "Sanity Token", "Strapi API Token",

            // Email Services (HIGH)
            "Postmark Server Token", "SparkPost API Key", "Mailjet API Secret", "Mandrill API Key", "Customer.io API Key",

            // Maps/Location
            "Mapbox Secret Token", "Here API Key", "TomTom API Key",

            // Social/OAuth Secrets
            "LinkedIn Client Secret", "Spotify Client Secret", "Dropbox App Secret",

            // Hardcoded Credentials
            "Private Key Inline", "Password Hardcoded", "Secret Key Hardcoded",
        }
        for _, name := range secretPatterns {
            if pattern, exists := regexPatterns[name]; exists {
                patternsToUse[name] = pattern
            }
        }
    }
    
    if config.Tokens {
        // JWT patterns
        jwtPattern := regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`)
        patternsToUse["JWT Token"] = jwtPattern
    }
    
    if config.Firebase {
        // Firebase patterns
        if pattern, exists := regexPatterns["Firebase"]; exists {
            patternsToUse["Firebase"] = pattern
        }
        if pattern, exists := regexPatterns["Firebase Url"]; exists {
            patternsToUse["Firebase Url"] = pattern
        }
    }
    
    if config.GraphQL {
        // GraphQL patterns - more specific to avoid jQuery false positives
        // Pattern 1: URLs containing /graphql path
        graphqlPattern1 := regexp.MustCompile(`(?i)["']([^"']*\/graphql[^"']*)["']`)
        patternsToUse["GraphQL URL"] = graphqlPattern1
        
        // Pattern 2: GraphQL endpoint in fetch/axios calls
        graphqlPattern2 := regexp.MustCompile(`(?i)(?:fetch|axios|request|post|get)\s*\([^)]*["']([^"']*\/graphql[^"']*)["']`)
        patternsToUse["GraphQL API Call"] = graphqlPattern2
        
        // Pattern 3: GraphQL variable assignments
        graphqlPattern3 := regexp.MustCompile(`(?i)(?:graphql|gql)[\s]*[:=][\s]*["']([^"']+)["']`)
        patternsToUse["GraphQL Endpoint"] = graphqlPattern3
        
        // Pattern 4: GraphQL query/mutation (NOT jQuery - must have query/mutation keyword)
        graphqlPattern4 := regexp.MustCompile(`(?i)\b(?:query|mutation|subscription)\s+\w+\s*\{[^}]+\}`)
        patternsToUse["GraphQL Query"] = graphqlPattern4
        
        // Pattern 5: GraphQL endpoint in config objects
        graphqlPattern5 := regexp.MustCompile(`(?i)["'](?:graphql_?endpoint|graphql_?url|graphql_?api|gql_?endpoint)["']\s*[:=]\s*["']([^"']+)["']`)
        patternsToUse["GraphQL Config"] = graphqlPattern5
    }
    
    if config.Links {
        // Extract URLs but exclude common trailing punctuation
        linkPattern := regexp.MustCompile(`(https?://[^\s"'<>,;\\()]+)`)
        patternsToUse["Link/URL"] = linkPattern
    }
    
    // Extract parameters - Advanced URL parameter detection with base URLs (new -PU flag)
    if config.ParamURLs {
        // Use advanced extraction that associates parameters with URLs
        paramURLs := extractURLParamsWithBaseURLs(string(body), source)
        
        // Global deduplication across all files
        globalSeenMutex.Lock()
        if len(paramURLs) > 0 {
            globalFoundAny = true // Mark that we found something
        }
        for _, paramURL := range paramURLs {
            // Only print if we haven't seen this URL before globally
            if !globalSeenAll[paramURL] {
                globalSeenAll[paramURL] = true
                fmt.Println(paramURL)
            }
        }
        globalSeenMutex.Unlock()
        // Return early - don't run sensitive data detection when using -PU flag
        // Return empty map to prevent any sensitive data from being printed
        return make(map[string][]string)
    }
    
    // Extract parameters - Basic parameter discovery (old -P flag behavior)
    if config.Params {
        paramSet := make(map[string]bool) // Use set to deduplicate
        
        // URL parameters: ?param=value or &param=value
        urlParamPattern := regexp.MustCompile(`[?&]([a-zA-Z0-9_\-]+)\s*=`)
        matches := urlParamPattern.FindAllStringSubmatch(string(body), -1)
        for _, match := range matches {
            if len(match) > 1 {
                param := strings.TrimSpace(match[1])
                if len(param) > 0 && len(param) < 100 {
                    paramSet[param] = true
                }
            }
        }
        
        // Function parameters in API calls: apiCall({param: value}) or apiCall("param", "value")
        funcParamPattern := regexp.MustCompile(`(?:get|post|put|delete|patch|fetch|axios|request)\s*\([^)]*["']([a-zA-Z0-9_\-]+)["']\s*[:=]`)
        matches = funcParamPattern.FindAllStringSubmatch(string(body), -1)
        for _, match := range matches {
            if len(match) > 1 {
                param := strings.TrimSpace(match[1])
                if len(param) > 0 && len(param) < 100 {
                    paramSet[param] = true
                }
            }
        }
        
        // Query string parameters: ?key=value patterns
        queryPattern := regexp.MustCompile(`["']([^"']*\?[a-zA-Z0-9_\-]+=)`)
        matches = queryPattern.FindAllStringSubmatch(string(body), -1)
        for _, match := range matches {
            if len(match) > 1 {
                queryStr := match[1]
                // Extract individual params from query string
                paramParts := regexp.MustCompile(`([a-zA-Z0-9_\-]+)=`).FindAllStringSubmatch(queryStr, -1)
                for _, part := range paramParts {
                    if len(part) > 1 {
                        param := strings.TrimSpace(part[1])
                        if len(param) > 0 && len(param) < 100 {
                            paramSet[param] = true
                        }
                    }
                }
            }
        }
        
        // Also look for common parameter patterns: paramName: or "paramName":
        commonParamPattern := regexp.MustCompile(`["']?([a-zA-Z0-9_\-]{2,50})["']?\s*[:=]\s*["']?[^"',}\s)]`)
        matches = commonParamPattern.FindAllStringSubmatch(string(body), -1)
        for _, match := range matches {
            if len(match) > 1 {
                param := strings.TrimSpace(match[1])
                // Filter out common JS keywords
                if len(param) > 1 && len(param) < 100 && 
                   param != "function" && param != "return" && param != "var" && 
                   param != "let" && param != "const" && param != "if" && 
                   param != "else" && param != "for" && param != "while" {
                    paramSet[param] = true
                }
            }
        }
        
        // Convert set to slice
        for param := range paramSet {
            matchesMap["Parameter"] = append(matchesMap["Parameter"], param)
        }
    }
    
    // Filter by domain scope
    if config.Domain != "" {
        if !strings.Contains(source, config.Domain) {
            return matchesMap
        }
    }
    
    // Filter by extension
    if config.Ext != "" {
        extList := strings.Split(config.Ext, ",")
        matched := false
        for _, ext := range extList {
            ext = strings.TrimSpace(ext)
            if strings.HasSuffix(source, ext) {
                matched = true
                break
            }
        }
        if !matched {
            return matchesMap
        }
    }
    
    // Run pattern matching
    bodyStr := string(body)
    sourceDomain := extractDomain(source)
    
    for name, pattern := range patternsToUse {
        if pattern.Match(body) {
            // Find all matches with their positions to check context
            allMatches := pattern.FindAllStringSubmatchIndex(bodyStr, -1)
            matches := []string{}
            
            for _, matchIndex := range allMatches {
                if len(matchIndex) >= 2 {
                    // Extract the match - use capture group if available, otherwise use full match
                    var match string
                    var start, end int
                    if len(matchIndex) >= 4 && matchIndex[2] != -1 && matchIndex[3] != -1 {
                        // Use first capture group if available
                        match = bodyStr[matchIndex[2]:matchIndex[3]]
                        start = matchIndex[2]
                        end = matchIndex[3]
                    } else {
                        // Use full match
                        match = bodyStr[matchIndex[0]:matchIndex[1]]
                        start = matchIndex[0]
                        end = matchIndex[1]
                    }
                    
                    // Check context around the match to see if it's part of a URL
                    
                    // Look at surrounding context (50 chars before and after for URL check)
                    contextStart := start - 50
                    if contextStart < 0 {
                        contextStart = 0
                    }
                    contextEnd := end + 50
                    if contextEnd > len(bodyStr) {
                        contextEnd = len(bodyStr)
                    }
                    context := bodyStr[contextStart:contextEnd]
                    
                    // Check if match is part of a URL in the context
                    if isMatchInURL(context, match, sourceDomain) {
                        continue // Skip this match - it's from a different domain URL
                    }
                    
                    // For base64 check, we need more context (200 chars before)
                    base64ContextStart := start - 200
                    if base64ContextStart < 0 {
                        base64ContextStart = 0
                    }
                    base64ContextEnd := end + 50
                    if base64ContextEnd > len(bodyStr) {
                        base64ContextEnd = len(bodyStr)
                    }
                    base64Context := bodyStr[base64ContextStart:base64ContextEnd]
                    
                    // Check if match is inside a base64 data URI (e.g., data:image/png;base64,...)
                    if isMatchInBase64DataURI(base64Context, match) {
                        continue // Skip this match - it's part of base64 encoded image/data
                    }
                    
                    // Check if match looks like base64-encoded media data (improved detection)
                    if isLikelyBase64MediaData(base64Context, match) {
                        continue // Skip this match - it's likely base64 encoded media content
                    }
                    
                    // For Links flag, clean up URLs and filter
                    if config.Links && (name == "Link/URL") {
                        // Clean trailing punctuation and invalid characters
                        match = cleanURL(match)
                        
                        // Skip if URL is empty after cleaning
                        if match == "" {
                            continue
                        }
                        
                        // Validate URL format (skip malformed URLs like http://example.com:80x/)
                        if !isValidURL(match) {
                            continue
                        }
                        
                        // Skip placeholder/template URLs (like http://servername:port/accountURL)
                        if isPlaceholderURL(match) {
                            continue
                        }
                        
                        // Check if URL is in a comment - skip if it is
                        if isURLInComment(context, match) {
                            continue
                        }
                        
                        // Filter: only show URLs from SAME base domain (user wants their own domain URLs)
                        // Skip external domains (like ad360plus.com, MuazKhan.com)
                        matchDomain := extractDomain(match)
                        if matchDomain != "" && sourceDomain != "" {
                            matchBaseDomain := extractBaseDomain(matchDomain)
                            sourceBaseDomain := extractBaseDomain(sourceDomain)
                            // Skip URLs from DIFFERENT base domains (external URLs)
                            if matchBaseDomain != sourceBaseDomain {
                                continue
                            }
                        }
                    }

                    // Filter unwanted emails
                    if name == "Email" && isUnwantedEmail(match) {
                        continue
                    }

                    matches = append(matches, match)
                }
            }
            
            if len(matches) > 0 {
                // Additional filtering for known false positives
                matches = filterMatchesByDomain(matches, source)
                
                if len(matches) > 0 {
                    if config.Regex != "" {
                        filterPattern, err := regexp.Compile(config.Regex)
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
                        matchesMap[name] = append(matchesMap[name], matches...)
                    }
                }
            }
        }
    }
    
    // Filter internal endpoints only
    if config.Internal {
        filtered := make(map[string][]string)
        for name, matches := range matchesMap {
            for _, match := range matches {
                if strings.Contains(match, "internal") || strings.Contains(match, "private") ||
                   strings.Contains(match, "127.0.0.1") || strings.Contains(match, "localhost") {
                    filtered[name] = append(filtered[name], match)
                }
            }
        }
        matchesMap = filtered
    }
    
    // Output formatting
    if len(matchesMap) > 0 {
        // Special handling for Params flag - just show parameter names, one per line
        if config.Params && len(matchesMap["Parameter"]) > 0 {
            // Global deduplication across all files
            globalSeenMutex.Lock()
            globalFoundAny = true // Mark that we found something
            for _, param := range matchesMap["Parameter"] {
                // Only print if we haven't seen this parameter before globally
                if !globalSeenParams[param] {
                    globalSeenParams[param] = true
                    fmt.Println(param)
                }
            }
            globalSeenMutex.Unlock()
            return matchesMap
        }
        
        if config.JSON {
            outputJSON(source, matchesMap)
        } else if config.CSV {
            outputCSV(source, matchesMap)
        } else if config.Burp {
            outputBurp(source, matchesMap)
        } else {
            // Show FOUND message (unless quiet mode)
            if !config.Quiet {
                fmt.Printf("[%s FOUND %s] Sensitive data at: %s\n", colors["RED"], colors["NC"], source)
            }
            // Global deduplication across all files
            globalSeenMutex.Lock()
            globalFoundAny = true // Mark that we found something
            for name, matches := range matchesMap {
                for _, match := range matches {
                    key := name + ":" + match
                    // Only print if we haven't seen this match before globally
                    if !globalSeenAll[key] {
                        globalSeenAll[key] = true
                        fmt.Printf("Sensitive Data [%s%s%s]: %s\n", colors["YELLOW"], name, colors["NC"], match)
                    }
                }
            }
            globalSeenMutex.Unlock()
        }
    } else {
        // Don't show MISSING if:
        // 1. FoundOnly flag is set
        // 2. ANY flag is set (Security Analysis OR JS Analysis flags)
        // 3. Quiet mode is enabled
        // MISSING messages should only show in pure "normal" mode (no flags at all)
        hasAnyFlag := config.Params || config.ParamURLs || config.Secrets || config.Tokens || 
                     config.GraphQL || config.Firebase || config.Links || config.Internal || 
                     config.Bypass || config.ExtractEndpoints || config.Deobfuscate || 
                     config.SourceMap || config.Eval || config.ObfsDetect
        
        // Buffer MISSING messages only for pure normal mode (no flags at all)
        if !config.FoundOnly && !hasAnyFlag && !config.Quiet {
            globalSeenMutex.Lock()
            foundAny := globalFoundAny
            globalSeenMutex.Unlock()
            
            // Only buffer if no findings have been made yet
            if !foundAny {
                missingMutex.Lock()
                missingMessages = append(missingMessages, source)
                missingMutex.Unlock()
            }
        }
    }
    
    return matchesMap
}

// Output formatters
func outputJSON(source string, matchesMap map[string][]string) {
    result := map[string]interface{}{
        "source": source,
        "matches": matchesMap,
    }
    jsonData, _ := json.MarshalIndent(result, "", "  ")
    fmt.Println(string(jsonData))
}

func outputCSV(source string, matchesMap map[string][]string) {
    writer := csv.NewWriter(os.Stdout)
    writer.Write([]string{"Source", "Type", "Value"})
    for name, matches := range matchesMap {
        for _, match := range matches {
            writer.Write([]string{source, name, match})
        }
    }
    writer.Flush()
}

func outputBurp(source string, matchesMap map[string][]string) {
    // Burp Suite format (simplified)
    for name, matches := range matchesMap {
        for _, match := range matches {
            fmt.Printf("%s\t%s\t%s\n", source, name, match)
        }
    }
}

// Wrapper functions using Config - enhanced versions
func processInputsWithConfig(url string, config *Config) {
    // Reset global state for new processing session
    globalSeenMutex.Lock()
    globalFoundAny = false
    globalSeenMutex.Unlock()
    missingMutex.Lock()
    missingMessages = missingMessages[:0]
    missingMutex.Unlock()
    
    // Use crawling if depth > 1
    if config.CrawlDepth > 1 && url != "" {
        visited := make(map[string]bool)
        crawlAndProcessJS(url, config, config.CrawlDepth, visited)
        return
    }
    
    var wg sync.WaitGroup
    urlChannel := make(chan string)

    var fileWriter *os.File
    if config.Output != "" {
        var err error
        fileWriter, err = os.Create(config.Output)
        if err != nil {
            fmt.Printf("Error creating output file: %v\n", err)
            return
        }
        defer fileWriter.Close()
    }

    for i := 0; i < config.Threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for u := range urlChannel {
                _, sensitiveData := searchForSensitiveDataWithConfig(u, config)

                // Don't print sensitive data if ParamURLs flag is set (user only wants URL params)
                if !config.ParamURLs {
                    if fileWriter != nil {
                        fmt.Fprintln(fileWriter, "URL:", u)
                        for name, matches := range sensitiveData {
                            for _, match := range matches {
                                fmt.Fprintf(fileWriter, "Sensitive Data [%s%s%s]: %s\n", colors["YELLOW"], name, colors["NC"], match)
                            }
                        }
                    }
                }
            }
        }()
    }

    if err := enqueueURLs(url, config.List, urlChannel, config.Regex); err != nil {
        fmt.Printf("Error in input processing: %v\n", err)
        close(urlChannel)
        return
    }

    close(urlChannel)
    wg.Wait()
    
    // Print buffered MISSING messages only if no findings were made
    // AND no flags are set (pure normal mode only)
    globalSeenMutex.Lock()
    foundAny := globalFoundAny
    globalSeenMutex.Unlock()
    
    hasAnyFlag := config.Params || config.ParamURLs || config.Secrets || config.Tokens || 
                 config.GraphQL || config.Firebase || config.Links || config.Internal || 
                 config.Bypass || config.ExtractEndpoints || config.Deobfuscate || 
                 config.SourceMap || config.Eval || config.ObfsDetect
    
    if !foundAny && !config.FoundOnly && !hasAnyFlag && !config.Quiet {
        missingMutex.Lock()
        for _, msg := range missingMessages {
            fmt.Printf("[%sMISSING%s] No sensitive data found at: %s\n", colors["BLUE"], colors["NC"], msg)
        }
        missingMessages = missingMessages[:0] // Clear the buffer
        missingMutex.Unlock()
    } else {
        // Clear the buffer if findings were made or specific flags are set
        missingMutex.Lock()
        missingMessages = missingMessages[:0]
        missingMutex.Unlock()
    }
}

func processInputsForEndpointsWithConfig(url string, config *Config) {
    // Use enhanced endpoint extraction with config
    var wg sync.WaitGroup
    urlChannel := make(chan string)
    
    var fileWriter *os.File
    if config.Output != "" {
        var err error
        fileWriter, err = os.Create(config.Output)
        if err != nil {
            fmt.Printf("Error creating output file: %v\n", err)
            return
        }
        defer fileWriter.Close()
    }
    
    for i := 0; i < config.Threads; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for u := range urlChannel {
                endpoints := extractEndpointsFromURLWithConfig(u, config)
                
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
    
    if err := enqueueURLs(url, config.List, urlChannel, config.Regex); err != nil {
        fmt.Printf("Error in input processing: %v\n", err)
        close(urlChannel)
        return
    }
    
    close(urlChannel)
    wg.Wait()
}

func processJSFileWithConfig(jsFile string, config *Config) {
    // Reset global state for new processing session
    globalSeenMutex.Lock()
    globalFoundAny = false
    globalSeenMutex.Unlock()
    missingMutex.Lock()
    missingMessages = missingMessages[:0]
    missingMutex.Unlock()
    
    if _, err := os.Stat(jsFile); os.IsNotExist(err) {
        fmt.Printf("[%sERROR%s] File not found: %s\n", colors["RED"], colors["NC"], jsFile)
    } else if err != nil {
        if !config.Quiet {
            fmt.Printf("[%sERROR%s] Unable to access file %s: %v\n", colors["RED"], colors["NC"], jsFile, err)
        }
    } else {
        if !config.Quiet {
            fmt.Printf("[%sFOUND%s] FILE: %s\n", colors["RED"], colors["NC"], jsFile)
        }
        searchForSensitiveDataWithConfig(jsFile, config)
        
        // Print buffered MISSING messages only if no findings were made
        // AND no flags are set (pure normal mode only)
        globalSeenMutex.Lock()
        foundAny := globalFoundAny
        globalSeenMutex.Unlock()
        
        hasAnyFlag := config.Params || config.ParamURLs || config.Secrets || config.Tokens || 
                     config.GraphQL || config.Firebase || config.Links || config.Internal || 
                     config.Bypass || config.ExtractEndpoints || config.Deobfuscate || 
                     config.SourceMap || config.Eval || config.ObfsDetect
        
        if !foundAny && !config.FoundOnly && !hasAnyFlag && !config.Quiet {
            missingMutex.Lock()
            for _, msg := range missingMessages {
                fmt.Printf("[%sMISSING%s] No sensitive data found at: %s\n", colors["BLUE"], colors["NC"], msg)
            }
            missingMessages = missingMessages[:0] // Clear the buffer
            missingMutex.Unlock()
        } else {
            // Clear the buffer if findings were made or specific flags are set
            missingMutex.Lock()
            missingMessages = missingMessages[:0]
            missingMutex.Unlock()
        }
    }
}

func processJSFileForEndpointsWithConfig(jsFile string, config *Config) {
    if _, err := os.Stat(jsFile); os.IsNotExist(err) {
        fmt.Printf("[%sERROR%s] File not found: %s\n", colors["RED"], colors["NC"], jsFile)
        return
    } else if err != nil {
        fmt.Printf("[%sERROR%s] Unable to access file %s: %v\n", colors["RED"], colors["NC"], jsFile, err)
        return
    }
    
    endpoints := extractEndpointsFromFile(jsFile, config.Regex)
    
    if config.Output != "" {
        writeEndpointsToFile(endpoints, config.Output, jsFile)
    } else {
        displayEndpoints(endpoints, jsFile)
    }
}

// extractEndpointsFromURLWithConfig enhanced endpoint extraction with config
func extractEndpointsFromURLWithConfig(urlStr string, config *Config) []string {
    client := createHTTPClientWithConfig(config)
    
    req, err := http.NewRequest("GET", urlStr, nil)
    if err != nil {
        return nil 
    }
    
    // Apply custom headers
    for _, header := range config.Headers {
        parts := strings.SplitN(header, ":", 2)
        if len(parts) == 2 {
            key := strings.TrimSpace(parts[0])
            value := strings.TrimSpace(parts[1])
            req.Header.Set(key, value)
            if config.Verbose {
                fmt.Printf("[%sINFO%s] Added header: %s: %s\n", colors["CYAN"], colors["NC"], key, value)
            }
        } else if config.Verbose {
            fmt.Printf("[%sWARN%s] Invalid header format (expected 'Key: Value'): %s\n", colors["YELLOW"], colors["NC"], header)
        }
    }
    
    // Apply custom User-Agent (randomly select from list if available)
    if len(config.UserAgents) > 0 {
        // Randomly select a user agent from the list for each request
        rand.Seed(time.Now().UnixNano() + int64(len(req.URL.String())))
        selectedUA := config.UserAgents[rand.Intn(len(config.UserAgents))]
        req.Header.Set("User-Agent", selectedUA)
        if config.Verbose {
            fmt.Printf("[%sINFO%s] Using User-Agent: %s\n", colors["CYAN"], colors["NC"], selectedUA)
        }
    } else if config.UserAgent != "" {
        req.Header.Set("User-Agent", config.UserAgent)
        if config.Verbose {
            fmt.Printf("[%sINFO%s] Using User-Agent: %s\n", colors["CYAN"], colors["NC"], config.UserAgent)
        }
    }
    
    if config.Cookies != "" {
        req.Header.Set("Cookie", config.Cookies)
    }
    
    resp, err := makeRequestWithRetry(client, req, config)
    if err != nil {
        // Don't show errors in quiet mode
        if !config.Quiet {
            if config.Verbose || config.Proxy == "" {
                if !isTLSCanceledError(err) {
                    fmt.Printf("[%sERROR%s] Request failed for %s: %v\n", colors["RED"], colors["NC"], urlStr, err)
                } else if config.Verbose {
                    fmt.Printf("[%sINFO%s] TLS connection canceled (proxy interception): %s\n", colors["YELLOW"], colors["NC"], urlStr)
                }
            } else if !isTLSCanceledError(err) {
                fmt.Printf("[%sERROR%s] Request failed for %s: %v\n", colors["RED"], colors["NC"], urlStr, err)
            }
        }
        return nil 
    }
    
    if config.Verbose {
        fmt.Printf("[%sINFO%s] Successfully fetched %s (Status: %d)\n", colors["GREEN"], colors["NC"], urlStr, resp.StatusCode)
    }
    defer resp.Body.Close()
    
    // Filter: Only process JavaScript content
    if !shouldProcessResponse(resp, urlStr, config) {
        return nil
    }
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        if len(body) == 0 {
            return nil 
        }
    }
    
    // Process JS analysis
    processedBody := processJSAnalysis(body, config)
    
    parsedURL, err := url.Parse(urlStr)
    if err != nil {
        return nil
    }
    baseURL := parsedURL.Scheme + "://" + parsedURL.Host
    
    return extractEndpointsFromContent(string(processedBody), config.Regex, baseURL)
}

// crawlAndProcessJS recursively crawls and processes JS files
func crawlAndProcessJS(initialURL string, config *Config, depth int, visited map[string]bool) {
    if depth <= 0 || visited[initialURL] {
        return
    }
    visited[initialURL] = true
    
    client := createHTTPClientWithConfig(config)
    req, err := http.NewRequest("GET", initialURL, nil)
    if err != nil {
        return
    }
    
    // Apply headers
    for _, header := range config.Headers {
        parts := strings.SplitN(header, ":", 2)
        if len(parts) == 2 {
            req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
        }
    }
    
    // Apply custom User-Agent (randomly select from list if available)
    if len(config.UserAgents) > 0 {
        // Randomly select a user agent from the list for each request
        rand.Seed(time.Now().UnixNano() + int64(len(req.URL.String())))
        selectedUA := config.UserAgents[rand.Intn(len(config.UserAgents))]
        req.Header.Set("User-Agent", selectedUA)
    } else if config.UserAgent != "" {
        req.Header.Set("User-Agent", config.UserAgent)
    }
    
    if config.Cookies != "" {
        req.Header.Set("Cookie", config.Cookies)
    }
    
    resp, err := makeRequestWithRetry(client, req, config)
    if err != nil {
        return
    }
    defer resp.Body.Close()
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return
    }
    
    // Process current page
    searchForSensitiveDataWithConfig(initialURL, config)
    
    // Find JS file references
    jsPattern := regexp.MustCompile(`(?:src|href)\s*=\s*["']([^"']+\.js[^"']*)["']`)
    matches := jsPattern.FindAllStringSubmatch(string(body), -1)
    
    parsedURL, err := url.Parse(initialURL)
    if err != nil {
        return
    }
    baseURL := parsedURL.Scheme + "://" + parsedURL.Host
    
    for _, match := range matches {
        if len(match) > 1 {
            jsURL := match[1]
            if !strings.HasPrefix(jsURL, "http") {
                if strings.HasPrefix(jsURL, "//") {
                    jsURL = parsedURL.Scheme + ":" + jsURL
                } else if strings.HasPrefix(jsURL, "/") {
                    jsURL = baseURL + jsURL
                } else {
                    jsURL = baseURL + "/" + jsURL
                }
            }
            
            // Check domain scope
            if config.Domain != "" && !strings.Contains(jsURL, config.Domain) {
                continue
            }
            
            // Check extension filter
            if config.Ext != "" {
                extList := strings.Split(config.Ext, ",")
                matched := false
                for _, ext := range extList {
                    ext = strings.TrimSpace(ext)
                    if strings.HasSuffix(jsURL, ext) {
                        matched = true
                        break
                    }
                }
                if !matched {
                    continue
                }
            }
            
            // Recursively process
            if !visited[jsURL] {
                crawlAndProcessJS(jsURL, config, depth-1, visited)
            }
        }
    }
}
