# jshunter

**jshunter** is a command-line tool designed for analyzing JavaScript files and extracting endpoints. This tool specializes in identifying sensitive data, such as API endpoints and potential security vulnerabilities, making it an essential resource for developers and security researchers.

## Features

- **Endpoint Extraction**: Automatically scans JavaScript files for URLs and API endpoints, allowing users to quickly identify potential points of interest.
- **Sensitive Data Detection**: The tool analyzes the JavaScript code to uncover hard-coded secrets, API keys, and other sensitive information that could lead to security breaches.
- **Customizable Options**: Users can specify various parameters, such as the number of threads for concurrent processing, cookies for authenticated sessions, and proxy settings for network configurations.
- **Flexible Input**: Supports input from single URLs, lists of URLs from text files, and direct JavaScript file paths, providing flexibility based on user needs.
- **Output Options**: Results can be saved to a specified output file, enabling easy access to the data extracted during the analysis.

## Usage Example

To use jshunter, run the following command:

```
cat urls.txt | grep "\.js" | jshunter
```
or
```
jshunter -u "https://example.com/javascript.js"
```
or
```
jshunter -l jsurls.txt
```
or
```
jshunter -f javascript.js
```

This command will analyze the specified JavaScript file and output the results to the console.

## Flags

- `-u, --url <URL>`: Input a URL to analyze.
- `-l, --list <file>`: Input a file with URLs (.txt) to analyze.
- `-f, --file <file>`: Path to a JavaScript file to analyze.
- `-o, --output <file>`: Where to save the output file (default: output.txt).
- `-t, --threads <number>`: Number of concurrent threads (default: 5).
- `-c, --cookies <cookies>`: Add cookies for authenticated JS files.
- `-p, --proxy <host:port>`: Set proxy (host:port).
- `-nc, --no-color`: Disable color output.
- `-q, --quiet`: Suppress ASCII art output.
- `-r, --regex <pattern>`: RegEx for filtering purposes against found endpoints.
- `-h, --help`: Display this help message.

## Install

You can either install using go:

```
go install -v github.com/cc1a2b/jshunter@latest
```

Or download a [binary release](https://github.com/cc1a2b/jshunter/releases) for your platform.






## License

ffuf is released under MIT license. See [LICENSE](https://github.com/cc1a2b/jshunter/blob/master/LICENSE).

