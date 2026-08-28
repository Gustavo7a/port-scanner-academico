package portscan_test

import (
	"testing"
	"time"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
)

func TestConnectRespeitaOTimeout(t *testing.T) {
	// 192.0.2.1 faz parte da faixa TEST-NET-1 (RFC 5737), reservada para
	// documentação. Nenhum roteador encaminha esse endereço, então a conexão
	// falha sem depender de internet.
	start := time.Now()
	connection, err := portscan.Connect("192.0.2.1", 80, 100*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		connection.Close()
		t.Fatal("Connect deveria falhar em um endereço sem rota")
	}
	if elapsed > time.Second {
		t.Fatalf("Connect demorou %v com timeout de 100ms e travaria o worker", elapsed)
	}
}
