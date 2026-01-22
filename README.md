# JSHunter

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.22.5+-00ADD8?style=flat&logo=go)](https://golang.org)
[![Release](https://img.shields.io/github/release/cc1a2b/jshunter.svg)](https://github.com/cc1a2b/jshunter/releases)
[![GitHub stars](https://img.shields.io/github/stars/cc1a2b/jshunter)](https://github.com/cc1a2b/jshunter/stargazers)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](https://github.com/cc1a2b/jshunter/releases)

**🔍 Professional JavaScript Security Analysis Tool**

*Complete endpoint discovery, sensitive data detection, and advanced code analysis for security professionals*

</div>

## 📖 About

**JSHunter** is a comprehensive command-line tool for JavaScript security analysis and endpoint discovery. Built for security professionals, penetration testers, and developers, it delivers enterprise-grade analysis capabilities with high accuracy detection algorithms and professional reporting features.

<div align="center">
<img alt="JSHunter Demo Screenshot" src="https://github.com/user-attachments/assets/f0197c36-c40b-48e9-bec5-c306acd4a613" width="100%">

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
- **🔍 Comprehensive Endpoint Discovery**: Automatically extracts URLs, API endpoints, and hidden parameters from JavaScript files
- **🔐 Advanced Security Analysis**: Identifies API keys, JWT tokens, credentials, and potential vulnerabilities with high accuracy  
- **📥 Flexible Input Methods**: Supports URLs, file lists, local files, stdin piping, and recursive discovery
- **⚡ High-Performance Architecture**: Multi-threaded concurrent processing with intelligent rate limiting
- **🎭 Professional Stealth Features**: Proxy support, custom headers, user-agent rotation, and bypass detection

### 🎯 Intelligent Detection Engine
> **Enterprise-grade accuracy with advanced analysis algorithms**

- **🎯 Smart Base64 Detection**: High-accuracy filtering eliminates false positives from media content and encoded data
- **🏢 Professional Interface**: Enterprise-ready terminology, documentation, and comprehensive reporting formats
- **🧠 Context-Aware Analysis**: Advanced algorithms distinguish real security tokens from encoded media data
- **📊 Entropy Analysis**: Mathematical algorithms identify genuine security tokens and credentials with precision

### 🌐 Professional HTTP & Networking Suite
<details>
<summary><strong>Enterprise-Grade Network Configuration</strong></summary>

**Authentication & Headers:**
- **🔧 Custom Headers** (`-H`): Repeatable authentication headers and custom request headers
- **🍪 Cookie Management** (`-c`): Session cookies for accessing protected resources
- **🎭 User-Agent Control** (`-U`): Custom UA strings or file-based rotation for stealth

**Performance & Reliability:**
- **⏱️ Rate Limiting** (`-R`): Configurable request delays (milliseconds) to avoid detection
- **⏰ Smart Timeouts** (`-T`): Custom timeout settings for different network conditions
- **🔄 Intelligent Retry** (`-y`): Automatic retry mechanism with exponential backoff for failed requests

**Professional Integration:**
- **🔗 Proxy Support** (`-p`): Full Burp Suite and custom proxy integration (HTTP/HTTPS/SOCKS5)
- **🔒 TLS Flexibility** (`-k`): Optional certificate verification bypass for testing environments
- **🎯 Thread Control** (`-t`): Configurable concurrent request handling for optimal performance

> **🔒 Security Professional Features**: Designed for penetration testing and security assessments  
> **Example**: `jshunter -l targets.txt -p 127.0.0.1:8080 -H "Authorization: Bearer token" -R 1000`

</details>

### 📝 Advanced JavaScript Analysis
<details>
<summary><strong>Complete Code Analysis & Deobfuscation Suite</strong></summary>

**Core Analysis Tools:**
- **🧩 Deobfuscation Engine** (`-d`): Unpacks minified and obfuscated JavaScript for deep analysis
- **🗺️ Source Map Parser** (`-m`): Extracts and analyzes original source code from source maps
- **🔍 Obfuscation Detection** (`-z`): Identifies and classifies obfuscation techniques and patterns

**Dynamic Analysis:**
- **⚡ Eval Analysis** (`-e`): Analyzes dynamic code execution (`eval()`, `Function()`, runtime generation)

**Code Intelligence:**
- **🔍 Pattern Recognition**: Identifies common JavaScript frameworks and libraries
- **📊 Code Structure Analysis**: Maps application architecture and data flows
- **🎯 Context-Aware Detection**: Understands code context to reduce false positives

> **💡 Professional Usage**: Combine analysis tools with security detection for maximum coverage  
> **Example**: `jshunter -u target.js -d -m -e -s -g` (full deobfuscation + security analysis)

</details>

### 🔐 Security Analysis Suite
<details>
<summary><strong>Complete Security Assessment Toolkit</strong></summary>

**Core Security Detection:**
- **🔑 Secrets Detection** (`-s`): API keys, access tokens, passwords, and hardcoded credentials
- **🎫 JWT Token Analysis** (`-x`): Authentication token extraction, validation, and payload inspection
- **🔥 Firebase Security** (`-F`): Configuration analysis, API keys, and database URL detection

**Advanced Analysis:**
- **📋 Parameter Discovery** (`-P`): Hidden form parameters, variables, and configuration keys
- **🔗 URL Parameter Extraction** (`-PU`): Advanced parameter analysis with full URL context
- **📊 GraphQL Analysis** (`-g`): Schema detection, query extraction, and endpoint discovery
- **🛡️ WAF Bypass Detection** (`-B`): Security bypass patterns and evasion techniques

**Scope & Context:**
- **🏠 Internal Endpoint Filtering** (`-i`): Private/internal resource identification and classification
- **🌐 Link Analysis** (`-L`): Comprehensive URL extraction and relationship mapping

> **🎯 Professional Tip**: Combine flags for comprehensive analysis (e.g., `jshunter -u target.js -s -x -F -g`)

</details>

### 🎯 Scope & Discovery
<details>
<summary><strong>Intelligent Crawling & Targeting</strong></summary>

- **🔍 Recursive Discovery**: Multi-depth JavaScript file crawling
- **🌍 Domain Scoping**: Focus analysis on specific domains
- **📂 Extension Filtering**: Target specific JavaScript file types

</details>

### 📤 Professional Reporting & Export Suite
<details>
<summary><strong>Enterprise-Grade Output & Integration</strong></summary>

**Core Output Formats:**
- **🖥️ Console Display**: Color-coded terminal output with professional formatting and clear categorization
- **📄 File Export** (`-o`): Save comprehensive results to custom file locations
- **📊 JSON Export** (`-j`): Structured data format for automation and programmatic processing
- **📈 CSV Export** (`-C`): Spreadsheet-compatible format for executive reporting and analysis

**Professional Integration:**
- **🔴 Burp Suite Export** (`-n`): Direct integration with Burp Suite Professional for immediate testing
- **🎯 Regex Filtering** (`-r`): Custom pattern matching for targeted result filtering
- **🔍 Verbose Analysis** (`-v`): Detailed analysis output with debugging information and context

**Result Management:**
- **✨ Clean Mode** (`--found-only`): Hide empty results for focused security reporting
- **🤫 Quiet Mode** (`-q`): Suppress banner for automated scripting and CI/CD integration

> **📋 Reporting Workflow**: Use JSON for automation, CSV for management reports, Burp export for immediate testing  
> **Example**: `jshunter -l targets.txt -s -j -o security-findings.json` (structured security report)

</details>

---

## 📦 Installation

### Go Install (Recommended)
```bash
# Install JSHunter
go install -v github.com/cc1a2b/jshunter@latest

# Verify installation
jshunter --help
```

### Build from Source
```bash
git clone https://github.com/cc1a2b/jshunter.git
cd jshunter
go build -o jshunter jshunter.go
```

### System Requirements
- **Go 1.22.5+** (for building from source)
- **Linux, macOS, or Windows** (64-bit architecture)
- **Network connectivity** for remote JavaScript analysis

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

### Complete Security Analysis
```bash
# Find API keys, secrets, and credentials
jshunter -u "https://target.com/app.js" -s

# Full analysis with deobfuscation, GraphQL, and Firebase detection
jshunter -u "https://target.com/app.js" -d -s -g -F -x -L

# Professional security assessment with all tools
jshunter -u "https://target.com/app.js" -d -m -e -s -x -P -g -F -B -L

# Export comprehensive results for reporting
jshunter -l targets.txt -s -g -F -j -o security_findings.json
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

# Complete security analysis - find secrets, API keys, and credentials
jshunter -u "https://example.com/app.js" -s -x -F

# Full analysis suite with deobfuscation and all security tools
jshunter -u "https://target.com/app.js" -d -m -e -s -x -P -g -F -B -L

# Professional assessment with source map analysis
jshunter -u "https://target.com/bundle.js" -d -m -s -g -F

# Export comprehensive results to structured formats
jshunter -l targets.txt -s -x -F -g -j -o security_findings.json

# Stealth scanning with Burp Suite integration
jshunter -l targets.txt -p 127.0.0.1:8080 -s -g -F -n -o burp_findings.txt

# Scanning through SOCKS5 proxy (Tor, SSH tunnel, etc.)
jshunter -l targets.txt -p socks5://127.0.0.1:9050 -s -x -F

# Rate-limited professional scanning with authentication
jshunter -l urls.txt -R 2000 -H "Authorization: Bearer token" -s -x -F -g -q

# Complete endpoint and parameter discovery
jshunter -l urls.txt -ep -P -PU -L -w 2

# Advanced obfuscation analysis with context detection
jshunter -f obfuscated.js -d -z -e -s -v
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
  -p, --proxy host:port        Proxy configuration (HTTP/HTTPS/SOCKS5, e.g., 127.0.0.1:8080 or socks5://127.0.0.1:1080)
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

### Professional Security Assessment
```bash
# Complete security analysis with all tools
jshunter -l targets.txt -d -m -e -z -s -x -P -PU -g -F -B -L -j -v -o complete_assessment.json

# Advanced deobfuscation and analysis pipeline
jshunter -l targets.txt -d -m -z -e -s -g -F --found-only -o deobfuscated_findings.json

# Stealth reconnaissance with rate limiting and custom headers
jshunter -l targets.txt -R 2000 -U "Mozilla/5.0..." -H "X-Forwarded-For: 1.1.1.1" -s -x -F -q

# Professional penetration testing through proxy
jshunter -l targets.txt -p 127.0.0.1:8080 -s -x -g -F -B -n -o burp_comprehensive.txt

# Deep parameter and endpoint discovery
jshunter -l targets.txt -ep -P -PU -L -w 3 -i -j -o endpoint_discovery.json
```

### Enterprise & Automation Integration
```bash
# CI/CD Security Pipeline Integration
jshunter -f dist/bundle.js -d -s -x -F -j --found-only > security-scan.json

# Comprehensive automated security reporting
jshunter -l production-js.txt -d -s -x -P -g -F -B -C -o enterprise-security-report.csv

# Source map analysis for development security
jshunter -f app.js -m -s -x -F -v -o sourcemap-analysis.json

# Firebase and GraphQL focused assessment
jshunter -l targets.txt -g -F -L -j -o api_security_findings.json
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
Copyright (c) 2024-2026 Hussain Alsharman
Licensed under MIT License - free for commercial and personal use
```

---

##  Support

If JSHunter helps with your security research or professional work:

<div align="center">

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/default-orange.png)](https://www.buymeacoffee.com/cc1a2b)

**⭐ Star this repo** • **🐦 Follow [@cc1a2b](https://twitter.com/cc1a2b)** • **📢 Share with others**

</div>

---

<div align="center">

**🔍 JSHunter - Professional JavaScript Security Analysis**

*Built with ❤️ by [cc1a2b](https://github.com/cc1a2b) for the security community*

</div>
