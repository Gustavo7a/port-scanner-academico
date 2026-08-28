package portscan

import "sort"

const (
	MinPort = 1
	MaxPort = 65535
)

const UnknownService = "unknown"

var commonPorts = map[int]string{
	20:    "ftp-data",
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	69:    "tftp",
	80:    "http",
	110:   "pop3",
	123:   "ntp",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	587:   "smtp-submission",
	636:   "ldaps",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgresql",
	5900:  "vnc",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	27017: "mongodb",
}

func ServiceName(port int) string {
	if name, ok := commonPorts[port]; ok {
		return name
	}
	return UnknownService
}

func DefaultPorts() []int {
	ports := make([]int, 0, len(commonPorts))
	for port := range commonPorts {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func IsValidPort(port int) bool {
	return port >= MinPort && port <= MaxPort
}
