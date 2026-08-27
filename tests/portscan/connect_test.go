package portscan_test

import (
	"net"
	"testing"
	"time"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
)

func TestConnectRetornaConexaoEmPortaAberta(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("não foi possível iniciar listener de teste: %v", err)
	}
	defer listener.Close()

	acceptDone := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			connection.Close()
		}
		close(acceptDone)
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	connection, err := portscan.Connect("127.0.0.1", port, time.Second)
	if err != nil {
		t.Fatalf("Connect devolveu erro inesperado: %v", err)
	}
	if connection == nil {
		t.Fatal("Connect devolveu conexão nula")
	}
	connection.Close()
	<-acceptDone
}

func TestConnectRetornaErroEmPortaFechada(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("não foi possível reservar porta de teste: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	connection, err := portscan.Connect("127.0.0.1", port, time.Second)
	if err == nil {
		t.Fatal("Connect deveria devolver erro para porta fechada")
	}
	if connection != nil {
		connection.Close()
		t.Fatal("Connect deveria devolver conexão nula em caso de erro")
	}
}
