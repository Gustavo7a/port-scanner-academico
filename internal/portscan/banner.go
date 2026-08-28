package portscan

import (
	"net"
	"strings"
	"time"
	"unicode"
)

const maxBannerSize = 1024

var httpPorts = map[int]bool{
	80:   true,
	8080: true,
	8000: true,
	8008: true,
}

// GrabBanner extrai o banner da conexão ativa e formata a saída.
func GrabBanner(conn net.Conn, timeout time.Duration) (string, error) {
	if conn == nil {
		return UnknownService, nil
	}

	port := remotePort(conn)

	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return ServiceName(port), nil
	}

	if httpPorts[port] {
		_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"))
	}

	buf := make([]byte, maxBannerSize)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		if port == 443 || port == 8443 {
			return "HTTPS / TLS (criptografado)", nil
		}
		return ServiceName(port), nil
	}
	if isTLSHandshake(buf[:n]) {
		return "HTTPS / TLS (criptografado)", nil
	}

	clean := sanitizeBanner(string(buf[:n]))
	if clean == "" {
		return ServiceName(port), nil
	}
	return clean, nil
}

func isTLSHandshake(data []byte) bool {
	return len(data) >= 3 && data[0] == 0x16 && data[1] == 0x03 && data[2] >= 0x00 && data[2] <= 0x04
}

func remotePort(conn net.Conn) int {
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcpAddr.Port
	}
	return 0
}

func sanitizeBanner(raw string) string {
	var builder strings.Builder
	for _, r := range raw {
		if unicode.IsSpace(r) {
			builder.WriteRune(' ')
		} else if unicode.IsPrint(r) {
			builder.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(builder.String()), " ")
}
