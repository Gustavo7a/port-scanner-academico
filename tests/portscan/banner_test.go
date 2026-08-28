package portscan_test

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
)

func TestGrabBannerIdentificaSSHESanitizaResposta(t *testing.T) {
	connection, done := serveBanner(t, 22, func(connection net.Conn) {
		_, _ = io.WriteString(connection, "SSH-2.0-OpenSSH_9.0\r\n")
	})

	banner, err := portscan.GrabBanner(connection, time.Second)
	if err != nil {
		t.Fatalf("GrabBanner devolveu erro: %v", err)
	}
	if banner != "SSH-2.0-OpenSSH_9.0" {
		t.Fatalf("banner = %q, esperado resposta SSH sanitizada", banner)
	}
	<-done
}

func TestGrabBannerFazRequisicaoHTTPERetornaResposta(t *testing.T) {
	connection, done := serveBanner(t, 80, func(connection net.Conn) {
		request, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr != nil {
			t.Errorf("servidor não recebeu requisição HTTP: %v", readErr)
			return
		}
		if !strings.HasPrefix(request, "HEAD / HTTP/1.0") {
			t.Errorf("requisição = %q, esperado HEAD / HTTP/1.0", request)
		}
		_, _ = io.WriteString(connection, "HTTP/1.1 200 OK\r\nServer: test-server\r\n\r\n")
	})

	banner, err := portscan.GrabBanner(connection, time.Second)
	if err != nil {
		t.Fatalf("GrabBanner devolveu erro: %v", err)
	}
	if banner != "HTTP/1.1 200 OK Server: test-server" {
		t.Fatalf("banner = %q, esperado resposta HTTP útil", banner)
	}
	<-done
}

func TestGrabBannerUsaServicoPadraoQuandoNaoHaResposta(t *testing.T) {
	connection, done := serveBanner(t, 22, func(connection net.Conn) {
		buffer := make([]byte, 1)
		_, _ = connection.Read(buffer)
	})

	start := time.Now()
	banner, err := portscan.GrabBanner(connection, 20*time.Millisecond)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GrabBanner devolveu erro: %v", err)
	}
	if banner != "ssh" {
		t.Fatalf("banner = %q, esperado fallback ssh", banner)
	}
	if elapsed > time.Second {
		t.Fatalf("leitura sem resposta demorou %v e pode bloquear o worker", elapsed)
	}
	<-done
}

func TestGrabBannerLimitaRespostaETLSForaDaPortaPadrao(t *testing.T) {
	response := []byte{0x16, 0x03, 0x03, 0x00, 0x10}
	connection, done := serveBanner(t, 4242, func(connection net.Conn) {
		_, _ = connection.Write(response)
	})

	banner, err := portscan.GrabBanner(connection, time.Second)
	if err != nil {
		t.Fatalf("GrabBanner devolveu erro: %v", err)
	}
	if banner != "HTTPS / TLS (criptografado)" {
		t.Fatalf("banner = %q, esperado identificação TLS", banner)
	}
	<-done
}

func TestGrabBannerLimitaQuantidadeLida(t *testing.T) {
	connection, done := serveBanner(t, 4242, func(connection net.Conn) {
		_, _ = io.WriteString(connection, strings.Repeat("a", 2048))
	})

	banner, err := portscan.GrabBanner(connection, time.Second)
	if err != nil {
		t.Fatalf("GrabBanner devolveu erro: %v", err)
	}
	if len(banner) != 1024 {
		t.Fatalf("tamanho do banner = %d, esperado 1024", len(banner))
	}
	<-done
}

func serveBanner(t *testing.T, port int, handler func(net.Conn)) (net.Conn, <-chan struct{}) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("não foi possível iniciar listener: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			handler(connection)
			connection.Close()
		}
		listener.Close()
	}()

	connection, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatalf("não foi possível conectar ao listener: %v", err)
	}
	return connectionWithRemotePort{Conn: connection, port: port}, done
}

type connectionWithRemotePort struct {
	net.Conn
	port int
}

func (connection connectionWithRemotePort) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: connection.port}
}
