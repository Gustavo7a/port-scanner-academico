package portscan

import (
	"net"
	"time"
)

// GrabBanner lê os primeiros bytes da conexão aberta para tentar identificar o serviço.
func GrabBanner(conn net.Conn, timeout time.Duration) (string, error) {
	return "", nil
}
