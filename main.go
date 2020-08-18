package main

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
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

func main() {
	// remove timestamp from logs
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	options := &goscan.Options{}
	flag.StringVar(&options.Range, "r", "", "IP/CIDR Range (Required)")
	flag.StringVar(&options.Ports, "p", "443", "Comma separated ports")
	flag.IntVar(&options.Timeout, "t", 300, "Timeout in milliseconds after request is sent")
	flag.IntVar(&options.Requests, "c", 500, "Requests per second")
	flag.Parse()

	if options.Range == "" {
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
