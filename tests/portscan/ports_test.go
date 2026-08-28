package portscan_test

import (
	"slices"
	"testing"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
)

func TestServiceNamePortasConhecidas(t *testing.T) {
	tests := []struct {
		port int
		want string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{27017, "mongodb"},
	}

	for _, tt := range tests {
		if got := portscan.ServiceName(tt.port); got != tt.want {
			t.Errorf("ServiceName(%d) = %q, esperado %q", tt.port, got, tt.want)
		}
	}
}

func TestServiceNamePortaDesconhecida(t *testing.T) {
	desconhecidas := []int{1, 4242, 65535}

	for _, port := range desconhecidas {
		if got := portscan.ServiceName(port); got != portscan.UnknownService {
			t.Errorf("ServiceName(%d) = %q, esperado %q", port, got, portscan.UnknownService)
		}
	}
}

func TestDefaultPortsVemOrdenadaEValida(t *testing.T) {
	ports := portscan.DefaultPorts()

	if len(ports) == 0 {
		t.Fatal("DefaultPorts() devolveu uma lista vazia")
	}
	if !slices.IsSorted(ports) {
		t.Errorf("DefaultPorts() = %v, esperava a lista ordenada", ports)
	}
	for _, port := range ports {
		if !portscan.IsValidPort(port) {
			t.Errorf("DefaultPorts() contém a porta inválida %d", port)
		}
		if portscan.ServiceName(port) == portscan.UnknownService {
			t.Errorf("a porta padrão %d não tem serviço associado", port)
		}
	}
}

func TestDefaultPortsDevolveCopiaIndependente(t *testing.T) {
	primeira := portscan.DefaultPorts()
	primeira[0] = 99999

	segunda := portscan.DefaultPorts()
	if segunda[0] == 99999 {
		t.Error("alterar o retorno de DefaultPorts() afetou as chamadas seguintes")
	}
}

func TestIsValidPort(t *testing.T) {
	tests := []struct {
		port int
		want bool
	}{
		{-1, false},
		{0, false},
		{1, true},
		{80, true},
		{65535, true},
		{65536, false},
	}

	for _, tt := range tests {
		if got := portscan.IsValidPort(tt.port); got != tt.want {
			t.Errorf("IsValidPort(%d) = %v, esperado %v", tt.port, got, tt.want)
		}
	}
}
