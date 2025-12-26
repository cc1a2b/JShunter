# jshunter

**jshunter** is a powerful command-line tool designed for comprehensive JavaScript security analysis and endpoint discovery. This tool specializes in identifying sensitive data, API endpoints, and potential security vulnerabilities, making it an essential resource for security professionals, penetration testers, and developers.

## Features

### Core Features
- **Endpoint Extraction**: Automatically scans JavaScript files for URLs and API endpoints, allowing users to quickly identify potential points of interest.
- **Sensitive Data Detection**: Analyzes JavaScript code to uncover hard-coded secrets, API keys, and other sensitive information that could lead to security breaches.
- **Flexible Input**: Supports input from single URLs, lists of URLs from text files, direct JavaScript file paths, and stdin piping.
- **Concurrent Processing**: Multi-threaded processing for efficient analysis of multiple files.

### v0.4 Improvements
- **Enhanced Base64 Detection**: Significantly reduced false positives from base64-encoded media content (images, videos, fonts)
- **Professional Interface**: Updated help text and terminology for professional security assessment use
- **Improved Context Analysis**: Better identification of encoded data vs. actual security tokens
- **Entropy Analysis**: Mathematical entropy calculation to distinguish real tokens from encoded data

### HTTP Configuration Options
- **Custom Headers**: Add custom HTTP headers (repeatable, including authentication headers).
- **User-Agent Customization**: Set custom User-Agent string or load from file (one per line).
- **Rate Limiting**: Configure delay between requests to avoid overwhelming servers.
- **Request Timeout**: Set custom timeout for HTTP requests.
- **Retry Mechanism**: Automatically retry failed requests.
- **Proxy Support**: Configure proxy settings (e.g., Burp Suite integration).
- **Cookie Support**: Add authentication cookies for protected JavaScript files.
- **TLS Verification**: Option to skip TLS certificate verification.

### JavaScript Analysis (Modifier Flags)
These flags modify JavaScript before analysis and work in combination with other flags or normal mode:
- **Deobfuscation**: Deobfuscate minified/obfuscated JavaScript code for better analysis.
- **Source Map Parsing**: Parse source maps to extract original JavaScript code.
- **Dynamic Code Analysis**: Analyze `eval()` and other dynamic code execution patterns.
- **Obfuscation Detection**: Detect various obfuscation techniques used in JavaScript files.

**Note**: JS Analysis flags are modifiers. Use them WITH Security Analysis flags (e.g., `jshunter -d -s` to deobfuscate and find secrets) or alone to deobfuscate and run all patterns.

### Security Analysis Features
- **Secrets Detection**: Identify API keys, tokens, and credentials in JavaScript files.
- **JWT/Auth Tokens**: Extract JWT and authentication tokens.
- **Hidden Parameters**: Discover hidden parameters and variables in JavaScript code.
- **Advanced URL Parameters**: Extract URL parameters with base URLs for comprehensive endpoint discovery.
- **Internal Endpoints**: Filter and extract only internal/private endpoints.
- **GraphQL Support**: Analyze GraphQL endpoints and queries.
- **WAF Bypass Patterns**: Detect WAF bypass patterns and techniques.
- **Firebase Detection**: Analyze Firebase configurations and secrets.
- **Link Extraction**: Extract and analyze all embedded links and URLs.

### Crawling & Scope
- **Recursive Crawling**: Recursively crawl JavaScript files with configurable depth.
- **Domain Scoping**: Scope analysis to specific domains.
- **File Extension Matching**: Match specific JavaScript file extensions.

### Output Formats
- **Standard Output**: Console output with color-coded results.
- **File Output**: Save results to specified output file.
- **JSON Output**: Structured JSON format for programmatic processing.
- **CSV Output**: CSV format for easy import into Excel/Google Sheets.
- **Verbose Mode**: Detailed analysis output with additional information.
- **Burp Suite Export**: Export results in Burp Suite compatible format.
- **Regex Filtering**: Filter results using custom regular expressions.
- **Found-Only Mode**: Only display results when sensitive data is found (hide MISSING messages).

![image](https://github.com/user-attachments/assets/563a36f0-3d68-4870-9f4a-4342aea2fa5f)


## Usage Examples

### Basic Usage

Analyze a single JavaScript file from URL:
```bash
jshunter -u "https://example.com/javascript.js"
```

Analyze multiple URLs from a file:
```bash
jshunter -l jsurls.txt
```

Analyze a local JavaScript file:
```bash
jshunter -f javascript.js
```

Pipe URLs from stdin (normal mode - shows all patterns):
```bash
cat urls.txt | grep "\.js" | jshunter
```

### Security Analysis (Specific Detection)

Find only secrets (API keys, tokens, credentials):
```bash
cat urls.txt | grep "\.js" | jshunter -s
```

Find only GraphQL endpoints:
```bash
cat urls.txt | grep "\.js" | jshunter -g
```

Find only Firebase configs:
```bash
cat urls.txt | grep "\.js" | jshunter -F
```

Extract links from same domain:
```bash
cat urls.txt | grep "\.js" | jshunter -L
```

Extract hidden parameters:
```bash
cat urls.txt | grep "\.js" | jshunter -P
```

Extract JWT tokens:
```bash
cat urls.txt | grep "\.js" | jshunter -x
```

### JS Analysis (Modifiers)

Deobfuscate and analyze (runs all patterns on deobfuscated code):
```bash
cat urls.txt | grep "\.js" | jshunter -d
```

Deobfuscate + find secrets:
```bash
cat urls.txt | grep "\.js" | jshunter -d -s
```

Parse source maps + find GraphQL:
```bash
cat urls.txt | grep "\.js" | jshunter -m -g
```

### Advanced Usage

Extract endpoints with custom headers and proxy:
```bash
jshunter -u "https://example.com/app.js" -H "Authorization: Bearer token" -p 127.0.0.1:8080
```

Recursive crawling with deobfuscation:
```bash
jshunter -u "https://example.com/main.js" -w 3 -d -v
```

Export to JSON with rate limiting:
```bash
jshunter -l urls.txt -j -R 1000 -o results.json
```

Burp Suite export format:
```bash
jshunter -l urls.txt -n -o burp_export.txt
```

### Flag Behavior

**Normal Mode** (no flags):
```bash
cat urls.txt | grep "\.js" | jshunter
```
- Searches for ALL patterns (secrets, tokens, emails, etc.)
- Shows `[MISSING]` messages when no findings

**With ANY Flag** (Security Analysis OR JS Analysis):
```bash
cat urls.txt | grep "\.js" | jshunter -s    # Secrets only
cat urls.txt | grep "\.js" | jshunter -g    # GraphQL only
cat urls.txt | grep "\.js" | jshunter -d    # Deobfuscate + all patterns
cat urls.txt | grep "\.js" | jshunter -L    # Links only
```
- No `[MISSING]` messages (cleaner output)
- Shows only `[FOUND]` when findings exist

**Security Analysis Flags** (`-s`, `-g`, `-L`, `-F`, `-x`, `-P`, etc.):
- Searches ONLY for the specific pattern requested
- Example: `-s` shows only secrets, `-g` shows only GraphQL

**JS Analysis Flags** (`-d`, `-m`, `-e`, `-z`):
- Modifier flags that preprocess JavaScript
- Used alone: runs all patterns on modified JS
- Combined with Security Analysis: runs specific patterns on modified JS
- Example: `-d -s` deobfuscates and finds secrets only

## Flags / Options

### Basic Options
- `-u, --url <URL>`: Input a URL to analyze.
- `-l, --list <file>`: Input a file with URLs (.txt) to analyze.
- `-f, --file <file>`: Path to a JavaScript file to analyze.
- `-t, --threads <number>`: Number of concurrent threads (default: 5).
- `-c, --cookies <cookies>`: Add cookies for authenticated JS files.
- `-p, --proxy <host:port>`: Set proxy (host:port), e.g., 127.0.0.1:8080 for Burp Suite.
- `-q, --quiet`: Suppress ASCII art output.
- `-o, --output <file>`: Output file path.
- `-r, --regex <pattern>`: RegEx for filtering results (endpoints and sensitive data).
- `--update, --up`: Update the tool to the latest version.
- `-ep, --end-point`: Extract endpoints from JavaScript files.
- `-k, --skip-tls`: Skip TLS certificate verification.
- `-fo, --found-only`: Only show results when sensitive data is found (hide MISSING messages).
- `-h, --help`: Display this help message.

### HTTP Configuration
- `-H, --header "Key: Value"`: Custom HTTP headers (repeatable, including authentication).
- `-U, --user-agent <UA>`: Custom User-Agent string or path to file containing user agents (one per line).
- `-R, --rate-limit <MS>`: Request rate limiting delay in milliseconds.
- `-T, --timeout <SEC>`: HTTP request timeout in seconds (default: 30).
- `-y, --retry <INT>`: Retry attempts for failed requests (default: 2).

### JavaScript Analysis
- `-d, --deobfuscate`: Deobfuscate minified and obfuscated JavaScript.
- `-m, --sourcemap`: Parse source maps for original code analysis.
- `-e, --eval`: Analyze dynamic code execution (eval, Function).
- `-z, --obfs-detect`: Detect code obfuscation patterns and techniques.

### Security Analysis
- `-s, --secrets`: Detect API keys, tokens, and credentials.
- `-x, --tokens`: Extract JWT and authentication tokens.
- `-P, --params`: Discover hidden parameters and variables.
- `-PU, --param-urls`: Advanced parameter extraction with URL context.
- `-i, --internal`: Filter for internal/private endpoints only.
- `-g, --graphql`: Analyze GraphQL endpoints and queries.
- `-B, --bypass`: Detect WAF bypass patterns and techniques.
- `-F, --firebase`: Analyze Firebase configurations and keys.
- `-L, --links`: Extract and analyze all embedded links.

### Scope & Discovery
- `-w, --crawl <DEPTH>`: Recursive JavaScript discovery depth (default: 1).
- `-D, --domain <DOMAIN>`: Limit analysis to specific domain.
- `-E, --ext <extensions>`: Filter by JavaScript file extensions (comma-separated).

### Output Formats
- `-j, --json`: Structured JSON output format.
- `-C, --csv`: CSV format for spreadsheet analysis.
- `-v, --verbose`: Detailed analysis and debug output.
- `-n, --burp`: Burp Suite compatible export format.


## Install

You can either install using go:

```
go install -v github.com/cc1a2b/jshunter@latest
```

Or download a [binary release](https://github.com/cc1a2b/jshunter/releases) for your platform.




## License

JShunter is released under MIT license. See [LICENSE](https://github.com/cc1a2b/jshunter/blob/master/LICENSE).





<a href="https://www.buymeacoffee.com/cc1a2b" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>
