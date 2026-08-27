package portscan

import (
	"net"
	"strconv"
	"time"
)

var DefaultDuration = 10 * time.Second

var dialTimeout = net.DialTimeout

// Connect tenta estabelecer uma conexão TCP e retorna a conexão ativa em caso de sucesso.
func Connect(ip string, port int, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = DefaultDuration
	}

	address := net.JoinHostPort(ip, strconv.Itoa(port))
	return dialTimeout("tcp", address, timeout)
}
