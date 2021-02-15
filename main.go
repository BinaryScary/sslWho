package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509/pkix"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BinaryScary/goscan"
	_ "github.com/mattn/go-sqlite3"
	// underscore import package soley for implementation
)

func logNames(cert tls.ConnectionState) {
	if len(cert.PeerCertificates[0].DNSNames) > 0 {
		log.Print(cert.PeerCertificates[0].DNSNames)
	}
	if len(cert.PeerCertificates[0].EmailAddresses) > 0 {
		log.Print(cert.PeerCertificates[0].EmailAddresses)
	}
	if len(cert.PeerCertificates[0].IPAddresses) > 0 {
		log.Print(cert.PeerCertificates[0].IPAddresses)
	}
	if len(cert.PeerCertificates[0].URIs) > 0 {
		log.Print(cert.PeerCertificates[0].URIs)
	}
	log.Print(cert.PeerCertificates[0].Subject.Names)
}

// golang doesn't have generics
func strArrToStr(arr []string) string {
	if len(arr) > 0 {
		return strings.Join(arr, " ")
	}

	return ""
}

func ipArrToStr(arr []net.IP) string {
	result := ""
	for _, i := range arr {
		result += i.String() + " "
	}

	return strings.TrimSpace(result)
}

func urlArrToStr(arr []*url.URL) string {
	result := ""
	for _, i := range arr {
		result += i.String() + " "
	}

	return strings.TrimSpace(result)
}

func nameArrToStr(arr []pkix.AttributeTypeAndValue) string {
	result := ""
	if len(arr) > 0 {
		return fmt.Sprintf("%s", arr)
	}

	return strings.TrimSpace(result)
}

func addCert(cert tls.ConnectionState, database *sql.DB, state goscan.PortState) {
	// UPSERT on conflict with compound key
	statement, _ := database.Prepare("INSERT INTO certs (host, port, dnsnames, emails, ipaddrs, uris, subnames) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(host,port) DO UPDATE SET dnsnames=EXCLUDED.dnsnames,emails=EXCLUDED.emails,ipaddrs=EXCLUDED.ipaddrs,uris=EXCLUDED.uris,subnames=EXCLUDED.subnames")
	host, port, dnsnames, emails, ipaddrs, uris, subnames := "", "", "", "", "", "", ""
	// if err != nil {
	// 	fmt.Print(err)
	// }

	host = state.Addr
	port = strconv.Itoa(state.Port)
	dnsnames = strArrToStr(cert.PeerCertificates[0].DNSNames)
	emails = strArrToStr(cert.PeerCertificates[0].EmailAddresses)
	ipaddrs = ipArrToStr(cert.PeerCertificates[0].IPAddresses)
	uris = urlArrToStr(cert.PeerCertificates[0].URIs)
	subnames = nameArrToStr(cert.PeerCertificates[0].Subject.Names)

	statement.Exec(host, port, dnsnames, emails, ipaddrs, uris, subnames)

}

func search(domain string, database *sql.DB, quiet bool) {
	query := "select * from certs where dnsnames LIKE ? OR emails LIKE ? OR uris LIKE ? OR subnames LIKE ?"
	rows, err := database.Query(query, domain, domain, domain, domain)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// remove all non-alphanumeric from string
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		log.Fatal(err)
	}
	pString := reg.ReplaceAllString(domain, "")

	// iterate through query result rows
	for rows.Next() {
		var (
			host     string
			port     int
			dnsnames string
			emails   string
			ipaddrs  string
			uris     string
			subnames string
		)
		// grab column values from row
		if err := rows.Scan(&host, &port, &dnsnames, &emails, &ipaddrs, &uris, &subnames); err != nil {
			log.Fatal(err)
		}

		if quiet {
			log.Printf("%s\n", host)
		} else {
			log.Printf("%s : ", host)
			if strings.Contains(dnsnames, pString) {
				log.Printf("	%s ", dnsnames)
			}
			if strings.Contains(emails, pString) {
				log.Printf("	%s ", emails)
			}
			if strings.Contains(uris, pString) {
				log.Printf("	%s ", uris)
			}
			if strings.Contains(subnames, pString) {
				log.Printf("	%s ", subnames)
			}
			// log.Printf("%s:	%s	%s	%s	%s\n", host, dnsnames, emails, uris, subnames)
		}
	}
}

func getBB(database *sql.DB) {
	resp, err := http.Get("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/master/data/wildcards.txt")
	if err != nil {
		log.Print("[!] error pulling bugbounty data")
	}
	defer resp.Body.Close()
	s := bufio.NewScanner(resp.Body)
	for s.Scan() {
		qString := strings.Replace(s.Text(), "*", "%", -1)
		qString += "%"

		query := "select * from certs where dnsnames LIKE ? OR emails LIKE ? OR uris LIKE ? OR subnames LIKE ?"
		rows, err := database.Query(query, qString, qString, qString, qString)
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		// iterate through query result rows
		for rows.Next() {
			var (
				host     string
				port     int
				dnsnames string
				emails   string
				ipaddrs  string
				uris     string
				subnames string
			)
			// grab column values from row
			if err := rows.Scan(&host, &port, &dnsnames, &emails, &ipaddrs, &uris, &subnames); err != nil {
				log.Fatal(err)
			}

			log.Printf("%s\n", host)
		}

	}
	if err := s.Err(); err != nil {
		log.Print("[!] error pulling bugbounty data")
	}

}

func logDomainIPs(domains []string, ip string, port int) {
	for _, s := range domains {
		log.Printf("%s,%s,%d", s, ip, port)
	}
}

// implement vhost checks
func getDomains(ipList string, database *sql.DB) {
	file, err := os.Open(ipList)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	r, _ := regexp.Compile("(\\w{2,63}[\\.])+\\w{2,63}")

	s := bufio.NewScanner(file)
	for s.Scan() {
		query := "select * from certs where host=?"
		rows, err := database.Query(query, s.Text())
		if err != nil {
			log.Fatal(err)
		}
		defer rows.Close()

		// iterate through query result rows
		for rows.Next() {
			var (
				host     string
				port     int
				dnsnames string
				emails   string
				ipaddrs  string
				uris     string
				subnames string
			)
			// grab column values from row
			if err := rows.Scan(&host, &port, &dnsnames, &emails, &ipaddrs, &uris, &subnames); err != nil {
				log.Fatal(err)
			}

			dNames := r.FindAllString(dnsnames, -1)
			dSubNames := r.FindAllString(subnames, -1)
			dUris := r.FindAllString(subnames, -1)
			logDomainIPs(dNames, s.Text(), port)
			logDomainIPs(dSubNames, s.Text(), port)
			logDomainIPs(dUris, s.Text(), port)
		}

	}
	if err := s.Err(); err != nil {
		log.Print("[!] error reading IPs from file")
	}
}

func main() {
	// remove timestamp from logs
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))
	log.SetOutput(os.Stdout)

	options := &goscan.Options{}
	flag.StringVar(&options.Range, "r", "", "IP/CIDR Range (Required)")
	flag.StringVar(&options.Ports, "p", "443", "Comma separated ports")
	flag.IntVar(&options.Timeout, "t", 300, "Timeout in milliseconds after request is sent")
	flag.IntVar(&options.Requests, "c", 500, "Requests per second")
	var query string
	flag.StringVar(&query, "s", "", "Run a search query on the database")
	var ipList string
	flag.StringVar(&ipList, "d", "", "Returns the domains found for a list of IPs")
	quiet := flag.Bool("q", false, "Output only IPs in search query")
	bb := flag.Bool("b", false, "Get all bugbounty IPs")

	flag.Parse()

	// check if a required flag is used
	if options.Range == "" && query == "" && !*bb && ipList == "" {
		flag.Usage()
		return
	}

	var ports []int
	sPorts := strings.Split(options.Ports, ",")
	ports = make([]int, len(sPorts))
	for i, s := range sPorts {
		ports[i], _ = strconv.Atoi(s)
	}

	database, _ := sql.Open("sqlite3", "./sslWho.db")
	defer database.Close()

	// query the database for specific domain
	if query != "" {
		search(query, database, *quiet)
		return
	}

	// print out bug bounty ips addresses
	if *bb {
		getBB(database)
		return
	}

	// print out domains for corresponding IPs in a list
	// usefully when trying to find vHosts
	if ipList != "" {
		getDomains(ipList, database)
		return
	}

	// compound key (host,port)
	statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS certs (host TEXT , port INT, dnsnames TEXT, emails TEXT, ipaddrs TEXT, uris TEXT, subnames TEXT, PRIMARY KEY (host,port))")
	statement.Exec()

	s := goscan.SetupScanner(options.Range, ports, options.Requests, options.Timeout)

	// TODO: add buffer so cert parse doesn't block PortState channel
	c := make(chan goscan.PortState, 100000)
	e := make(chan error, 1)
	go s.Scan(c, e)
	// range over channel only returns one variable

	// requests requests per second
	rps := time.Tick(time.Second / time.Duration(s.Rps))
	for i := range c {
		go func(i goscan.PortState) {
			<-rps
			if i.State == 0 {
				log.Printf("%s port %v open", i.Addr, i.Port)

				// does not supply SNI therefore IP's with multiple certificates (virtualhosts) will not return proper cert, SNI requires a hostname not a IP
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%v", i.Addr, i.Port), time.Duration(options.Timeout)*time.Millisecond)
				if err != nil {
					log.Printf("timeout on %s: %v", i.Addr, err)
					return
				}
				tlsconn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
				err = tlsconn.Handshake()
				if err != nil {
					conn.Close()
					log.Printf("cert Failed on %s: %v", i.Addr, err)
					return
				}
				cert := tlsconn.ConnectionState()
				// logNames(cert)
				addCert(cert, database, i)
				conn.Close()
				tlsconn.Close()
			}
			if i.State == 1 {
				log.Printf("%s port %v closed", i.Addr, i.Port)
			}
		}(i)
	}

	err := <-e
	if err != nil {
		log.Printf("unable to scan %s: %v", s.Dst.String(), err)
	}
}
