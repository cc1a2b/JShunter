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

### Method 2: Binary Releases
Download pre-compiled binaries from [GitHub Releases](https://github.com/cc1a2b/jshunter/releases)

```bash
# Linux/macOS
wget https://github.com/cc1a2b/jshunter/releases/latest/download/jshunter-linux-amd64
chmod +x jshunter-linux-amd64
sudo mv jshunter-linux-amd64 /usr/local/bin/jshunter

# Windows (PowerShell)
Invoke-WebRequest -Uri "https://github.com/cc1a2b/jshunter/releases/latest/download/jshunter-windows-amd64.exe" -OutFile "jshunter.exe"
```

### Method 3: Build from Source
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

```bash
# Analyze single URL
jshunter -u "https://example.com/app.js"

# Analyze multiple URLs from file
jshunter -l urls.txt

# Pipe URLs from stdin
cat urls.txt | grep "\.js" | jshunter

# Find secrets and API keys
jshunter -u "https://example.com/app.js" -s

# Comprehensive security analysis with deobfuscation
jshunter -u "https://target.com/app.js" -d -s -g -F

# Export results to JSON
jshunter -l targets.txt -s -j -o findings.json

# Use with Burp Suite proxy
jshunter -l targets.txt -p 127.0.0.1:8080 -s -n -o burp_findings.txt

# Rate-limited scanning with custom headers
jshunter -l urls.txt -R 2000 -H "Authorization: Bearer token" -s -q
```

---

## 📋 Command Reference

Get the complete help anytime with `jshunter --help`

```
Usage:
  -u, --url URL                 Input a URL
  -l, --list FILE.txt           Input a file with URLs (.txt)
  -f, --file FILE.js            Path to JavaScript file

Basic Options:
  -t, --threads INT             Number of concurrent threads (default: 5)
  -c, --cookies <cookies>      Authentication cookies for protected resources
  -p, --proxy host:port        HTTP proxy configuration (e.g., 127.0.0.1:8080 for Burp Suite)
  -q, --quiet                  Suppress ASCII art output
  -o, --output FILENAME.txt    Output file path
  -r, --regex <pattern>        RegEx for filtering results (endpoints and sensitive data)
  --update, --up               Update the tool to latest version
  -ep, --end-point             Extract endpoints from JavaScript files
  -k, --skip-tls               Skip TLS certificate verification
  -fo, --found-only            Only show results when sensitive data is found (hide MISSING messages)

HTTP Configuration:
  -H, --header "Key: Value"    Custom HTTP headers (repeatable, including Auth)
  -U, --user-agent UA          Custom User-Agent string or file path (one per line)
  -R, --rate-limit MS          Request rate limiting delay (milliseconds)
  -T, --timeout SEC            HTTP request timeout (seconds)
  -y, --retry INT              Retry attempts for failed requests (default: 2)

JavaScript Analysis:
  -d, --deobfuscate            Deobfuscate minified and obfuscated JavaScript
  -m, --sourcemap              Parse source maps for original code analysis
  -e, --eval                   Analyze dynamic code execution (eval, Function)
  -z, --obfs-detect            Detect code obfuscation patterns and techniques

Security Analysis:
  -s, --secrets                Detect API keys, tokens, and credentials
  -x, --tokens                 Extract JWT and authentication tokens
  -P, --params                 Discover hidden parameters and variables
  -PU, --param-urls            Advanced parameter extraction with URL context
  -i, --internal               Filter for internal/private endpoints
  -g, --graphql                Analyze GraphQL endpoints and queries
  -B, --bypass                 Detect WAF bypass patterns and techniques
  -F, --firebase               Analyze Firebase configurations and keys
  -L, --links                  Extract and analyze all embedded links

Scope & Discovery:
  -w, --crawl DEPTH            Recursive JavaScript discovery depth (default: 1)
  -D, --domain DOMAIN          Limit analysis to specific domain
  -E, --ext                    Filter by JavaScript file extensions

Output Formats:
  -j, --json                   Structured JSON output format
  -C, --csv                    CSV format for spreadsheet analysis
  -v, --verbose                Detailed analysis and debug output
  -n, --burp                   Burp Suite compatible export format
  -h, --help                   Display this help message
```

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