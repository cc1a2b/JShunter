# jshunter

jshunter is a command-line tool designed for analyzing JavaScript files and extracting endpoints.

## Usage Example

To use jshunter, run the following command:

```
▶ go run jshunter.go -u "https://khadamati.moe.gov.sa/scripts/javascript.js"
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

