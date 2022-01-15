# sshBruteforcer
A small GoLang app which can bruteforce ssh credentials, was used before for a ctf and is now optimized for future ctf events.

## Features:
```
 [#]  Wordlist usage
 [#]  Workers
 [#]  Comand-line arguments
 [#]  Inverted Bruteforce (Username missing, known password)
 [#]  Socket5 Proxy
 [ ]  Socket5 Proxy List
 [ ]  Fail2Ban detection and switch Proxy
 [ ]  Automated flag dumping ( ssh to machine and `find ...` it)
```

## Usage

```bash
go build
./sshMultiThreadedBruteForcer -h
```

```txt
flag needs an argument: -h
  -c int
        Specify Worker count. Default is 10 (default 22)
  -h string
        Specify Hostname or ip. Default is 127.0.0.1 (default "127.0.0.1")      
  -i    Specify Inversion mode, bruteforce username with one password. Default i
s false
  -p int
        Specify Port. Default is 22 (default 22)
  -proxy string
        Specify proxy in format ip:port. Default is no proxy usage
  -proxy-credentials string
        Specify proxy credentials in format username:password. Default is empty 
  -t int
        Specify Timeout. Default is 3 (default 3)
  -u string
        Specify username or password (depends on inverted flag). Default is root
 (default "root")
  -w string
        Specify wordlist. Default is ./smalllist.txt (default "./smalllist.txt")
```



## Info
This tool is created strictly for CTF purpose.