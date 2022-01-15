# sshBruteforcer
A small GoLang app which can bruteforce ssh credentials, was used before for a ctf and is now optimized for future ctf events.

## Features:
Implement the Feature: https://gist.github.com/ometa/71d23ed48c03c003f6e4910648612859
```
 [#]  Wordlist usage
 [#]  Workers
 [#]  Comand-line arguments
 [ ]  Inverted Bruteforce (Username missing, known password)
 [ ]  Socket5 Proxy
 [ ]  Socket5 Proxy List
 [ ]  Fail2Ban detection and switch Proxy
 [ ]  Automated flag dumping ( ssh to machine and `find ...` it)
```

## Usage

```bash
go build
./sshBruteforcer -h
```


## Info
This tool is created strictly for CTF purpose.