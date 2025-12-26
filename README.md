# JSHunter

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22.5+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/release/cc1a2b/jshunter.svg)](https://github.com/cc1a2b/jshunter/releases)
[![GitHub stars](https://img.shields.io/github/stars/cc1a2b/jshunter)](https://github.com/cc1a2b/jshunter/stargazers)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/cc1a2b/jshunter/releases)

**🔍 Professional JavaScript Security Analysis Tool**

*Comprehensive endpoint discovery and sensitive data detection for security professionals*

</div>

## 📖 About

**JSHunter** is a powerful command-line tool designed for comprehensive JavaScript security analysis and endpoint discovery. This tool specializes in identifying sensitive data, API endpoints, and potential security vulnerabilities, making it an essential resource for security professionals, penetration testers, and developers.

<div align="center">
<img alt="JSHunter Demo Screenshot" src="https://github.com/user-attachments/assets/e5053a75-58f9-4027-8d21-9525cc5e3b1f" width="100%">

*JSHunter in action - Professional JavaScript security analysis*
</div>

---

## 📑 Table of Contents

- [About](#-about)
- [Features](#-features)
- [Installation](#-installation)  
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Command Reference](#-command-reference)
- [Advanced Usage](#-advanced-usage)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

---

## ✨ Features

### 🎯 Core Capabilities
- **🔍 Endpoint Discovery**: Automatically scans JavaScript files for URLs and API endpoints
- **🔐 Sensitive Data Detection**: Identifies hard-coded secrets, API keys, and security vulnerabilities  
- **📥 Flexible Input**: Support for URLs, file lists, local files, and stdin piping
- **⚡ High Performance**: Multi-threaded concurrent processing for speed

### 🚀 Version 0.4 Highlights
> **Major improvements focusing on accuracy and professional use**

- **🎯 Enhanced Base64 Detection**: ~90% reduction in false positives from media content
- **🏢 Professional Interface**: Enterprise-ready terminology and documentation
- **🧠 Smart Context Analysis**: Advanced identification of real tokens vs. encoded data
- **📊 Entropy Analysis**: Mathematical algorithms to distinguish security tokens from media

### 🌐 HTTP Configuration
<details>
<summary><strong>Advanced HTTP Options</strong></summary>

- **🔧 Custom Headers**: Repeatable authentication and custom headers
- **🎭 User-Agent Control**: Custom UA strings or file-based rotation  
- **⏱️ Rate Limiting**: Configurable delays to avoid overwhelming targets
- **⏰ Smart Timeouts**: Custom timeout settings for reliability
- **🔄 Auto Retry**: Intelligent retry mechanism for failed requests
- **🔗 Proxy Support**: Burp Suite and custom proxy integration
- **🍪 Cookie Management**: Authentication cookies for protected resources
- **🔒 TLS Flexibility**: Optional certificate verification bypass

</details>

### 📝 JavaScript Analysis
<details>
<summary><strong>Code Processing & Deobfuscation</strong></summary>

**Modifier flags that enhance analysis accuracy:**

- **🧩 Deobfuscation**: Unpack minified/obfuscated JavaScript for deeper analysis
- **🗺️ Source Map Parsing**: Extract original code from source maps
- **⚡ Dynamic Code Analysis**: Analyze `eval()` and runtime code generation
- **🔍 Obfuscation Detection**: Identify and classify obfuscation techniques

> **💡 Pro Tip**: Combine with Security Analysis flags (e.g., `jshunter -d -s`) for enhanced detection

</details>

### 🔐 Security Analysis
<details>
<summary><strong>Professional Security Assessment Features</strong></summary>

- **🔑 Secrets Detection**: API keys, tokens, and credentials identification
- **🎫 JWT Analysis**: Authentication token extraction and analysis
- **📋 Parameter Discovery**: Hidden parameters and variables detection
- **🔗 URL Parameter Extraction**: Advanced parameter analysis with context
- **🏠 Internal Endpoint Filtering**: Private/internal resource identification
- **📊 GraphQL Analysis**: Query and endpoint detection for GraphQL APIs
- **🛡️ WAF Bypass Detection**: Security bypass pattern identification
- **🔥 Firebase Analysis**: Configuration and secret detection
- **🌐 Link Analysis**: Comprehensive URL and link extraction

</details>

### 🎯 Scope & Discovery
<details>
<summary><strong>Intelligent Crawling & Targeting</strong></summary>

- **🔍 Recursive Discovery**: Multi-depth JavaScript file crawling
- **🌍 Domain Scoping**: Focus analysis on specific domains
- **📂 Extension Filtering**: Target specific JavaScript file types

</details>

### 📤 Output Formats
<details>
<summary><strong>Professional Reporting & Integration</strong></summary>

- **🖥️ Console Output**: Color-coded terminal results with clear formatting
- **📄 File Export**: Save results to custom file locations
- **📊 JSON Export**: Structured data for programmatic processing
- **📈 CSV Export**: Spreadsheet-compatible format for analysis
- **🔍 Verbose Mode**: Detailed analysis with debugging information
- **🔴 Burp Suite Export**: Direct integration with Burp Suite Professional
- **🎯 Regex Filtering**: Custom pattern matching for targeted results
- **✨ Clean Mode**: Hide empty results for focused reporting

</details>

---

## 📦 Installation

### Method 1: Go Install (Recommended)
```bash
# Install latest version
go install -v github.com/cc1a2b/jshunter@latest

# Verify installation
jshunter --help
```

### Method 2: Build from Source
```bash
git clone https://github.com/cc1a2b/jshunter.git
cd jshunter
go build -o jshunter jshunter.go
```

### Requirements
- **Go 1.22.5+** (for source installation)
- **Linux, macOS, or Windows** (64-bit)
- **Internet connection** for URL analysis

---

## 🚀 Quick Start

### Basic Analysis
```bash
# Analyze a single JavaScript file
jshunter -u "https://example.com/app.js"

# Scan multiple URLs from file
jshunter -l urls.txt

# Analyze local JavaScript file
jshunter -f app.js
```

### Professional Security Assessment
```bash
# Find API keys and secrets
jshunter -u "https://target.com/app.js" -s

# Comprehensive analysis with deobfuscation
jshunter -u "https://target.com/app.js" -d -s -g -F

# Export results for reporting
jshunter -l targets.txt -s -j -o security_findings.json
```

---

## 💡 Usage Examples

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

---

## 📋 Command Reference

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

---

## 🔧 Advanced Usage

### Professional Penetration Testing
```bash
# Full security assessment pipeline
jshunter -l targets.txt -d -s -g -F -L -j -v -o full_assessment.json

# Stealth scanning with rate limiting
jshunter -l targets.txt -R 2000 -U "Mozilla/5.0..." -s -q

# Through Burp Suite proxy
jshunter -l targets.txt -p 127.0.0.1:8080 -s -g -n -o burp_findings.txt
```

### Enterprise Integration
```bash
# CI/CD Pipeline Integration
jshunter -f dist/app.js -s -j --found-only > security-scan.json

# Automated Reporting
jshunter -l production-js.txt -s -F -C -o security-report.csv
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

- **🐛 Report bugs** via [GitHub Issues](https://github.com/cc1a2b/jshunter/issues)
- **💡 Suggest features** or improvements
- **📝 Improve documentation** 
- **🔧 Submit pull requests** with enhancements

### Development Setup
```bash
git clone https://github.com/cc1a2b/jshunter.git
cd jshunter
go mod tidy
go build -o jshunter jshunter.go
```

---

## 📄 License

JSHunter is released under the **MIT License**. See [LICENSE](https://github.com/cc1a2b/jshunter/blob/master/LICENSE) for details.

```
Copyright (c) 2024 Hussain Alsharman
Licensed under MIT License - free for commercial and personal use
```

---

## 💖 Support

If JSHunter helps with your security research or professional work:

<div align="center">

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/default-orange.png)](https://www.buymeacoffee.com/cc1a2b)

**⭐ Star this repo** • **🐦 Follow [@cc1a2b](https://twitter.com/cc1a2b)** • **📢 Share with others**

</div>

---

<div align="center">

**🔍 JSHunter v0.4 - Professional JavaScript Security Analysis**

*Built with ❤️ by [cc1a2b](https://github.com/cc1a2b) for the security community*

</div>
