package worker_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
	"github.com/joaofamello/port-scanner-academico/internal/worker"
)

// startLocalService sobe um servidor TCP em uma porta livre de 127.0.0.1 e
// devolve a porta escolhida. Quando banner não é vazio, o servidor escreve esse
// texto em cada conexão aceita.
func startLocalService(t *testing.T, banner string) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("não foi possível iniciar o serviço local: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			if banner != "" {
				_, _ = io.WriteString(connection, banner)
			}
			connection.Close()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

// reservePort abre e fecha um listener só para descobrir uma porta que ninguém
// está escutando, garantindo uma porta fechada de verdade.
func reservePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("não foi possível reservar a porta: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

func TestStartScanComServicoLocalClassificaAbertaEFechada(t *testing.T) {
	openPort := startLocalService(t, "")
	closedPort := reservePort(t)

	results := worker.StartScan("127.0.0.1", []int{openPort, closedPort}, worker.PoolConfig{
		NumWorkers: 2,
		Timeout:    time.Second,
	})

	if len(results) != 2 {
		t.Fatalf("quantidade de resultados = %d, esperado 2", len(results))
	}
	if results[0].Port != openPort || results[0].Status != portscan.StatusOpen || !results[0].IsOpen {
		t.Errorf("porta aberta classificada incorretamente: %+v", results[0])
	}
	if results[1].Port != closedPort || results[1].Status != portscan.StatusClosed || results[1].IsOpen {
		t.Errorf("porta fechada classificada incorretamente: %+v", results[1])
	}
}

func TestStartScanCapturaBannerDoServicoLocal(t *testing.T) {
	port := startLocalService(t, "SSH-2.0-OpenSSH_9.0\r\n")

	results := worker.StartScan("127.0.0.1", []int{port}, worker.PoolConfig{
		NumWorkers:    1,
		Timeout:       time.Second,
		CaptureBanner: true,
	})

	if results[0].Banner != "SSH-2.0-OpenSSH_9.0" {
		t.Fatalf("banner = %q, esperado a resposta do serviço local", results[0].Banner)
	}
}

func TestStartScanNaoCapturaBannerQuandoDesligado(t *testing.T) {
	port := startLocalService(t, "SSH-2.0-OpenSSH_9.0\r\n")

	results := worker.StartScan("127.0.0.1", []int{port}, worker.PoolConfig{
		NumWorkers: 1,
		Timeout:    time.Second,
	})
	if results[0].Banner != "" {
		t.Fatalf("banner = %q, esperado vazio com a captura desligada", results[0].Banner)
	}
}
