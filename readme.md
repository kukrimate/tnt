# TNT
TNT is a minimalist, multi-threaded web fuzzer written in C.

## DISCLAIMER
This tool is designed for security testing. If you use this tool, it is **your**
responsibility to make sure you have permission to use it on the target system.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR THE (MIS)USE OF THIS TOOL.

## Usage
Clone the repository, build with `make`. Either install the TNT binary
using `make install` or just run it from the build directory.

It accepts the following options:
- `-t`: optional, changes the number of threads, by default it's set to `nproc`
- `-i`; optional, if set than certificate errors will be ignored when using TLS
- `-w`: required, the wordlist file, it should contain newline separated words,
	the words are used to replace `FUZZ` in the URL template
- `-u`: required, the target URL template, must include the word `FUZZ`, e.g.
	`http://localhost/FUZZ.html`

## Copying
TNT is released under the ISC license. Check `license.txt` for more details.
