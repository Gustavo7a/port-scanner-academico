package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/joaofamello/port-scanner-academico/internal/parser"
	"github.com/joaofamello/port-scanner-academico/internal/portscan"
)

func TestRunExibeAjudaSemErro(t *testing.T) {
	var output bytes.Buffer

	if err := run([]string{"-h", "--help"}, &output); err != nil {
		t.Fatalf("run com -h/--help retornou erro: %v", err)
	}

	text := output.String()
	for _, expected := range []string{"Uso:", "-t, --target", "-p, --ports", "Exemplos:"} {
		if !strings.Contains(text, expected) {
			t.Errorf("a ajuda não contém %q: %q", expected, text)
		}
	}
}

func TestRunRejeitaParametrosInvalidos(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr error
	}{
		{"sem alvo", []string{"-p", "80"}, ErrMissingTarget},
		{"workers zero", []string{"-t", "127.0.0.1", "-w", "0"}, ErrInvalidWorkers},
		{"workers negativo", []string{"-t", "127.0.0.1", "-w", "-3"}, ErrInvalidWorkers},
		{"timeout zero", []string{"-t", "127.0.0.1", "-T", "0s"}, ErrInvalidTimeout},
		{"porta fora do intervalo", []string{"-t", "127.0.0.1", "-p", "70000"}, parser.ErrInvalidPort},
		{"intervalo invertido", []string{"-t", "127.0.0.1", "-p", "90-80"}, parser.ErrInvalidRange},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer

			err := run(tt.args, &output)
			if err == nil {
				t.Fatalf("run(%v) não devolveu erro", tt.args)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("run(%v) devolveu %v, esperava %v", tt.args, err, tt.wantErr)
			}
			if !strings.Contains(output.String(), "Uso:") {
				t.Error("run deveria imprimir a ajuda quando os parâmetros estão errados")
			}
		})
	}
}

func TestRunAceitaFormaCurtaELonga(t *testing.T) {
	port := strconv.Itoa(portaFechada(t))

	tests := map[string][]string{
		"forma curta": {"-t", "127.0.0.1", "-p", port, "-w", "3", "-T", "200ms"},
		"forma longa": {"--target", "127.0.0.1", "--ports", port, "--workers", "3", "--timeout", "200ms"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer

			if err := run(args, &output); err != nil {
				t.Fatalf("run(%v) devolveu erro: %v", args, err)
			}
			if !strings.Contains(output.String(), "Workers: 3 | Timeout: 200ms") {
				t.Fatalf("cabeçalho não refletiu as opções: %q", output.String())
			}
		})
	}
}

func TestRunUsaPortasPadraoQuandoOpcaoAusente(t *testing.T) {
	var output bytes.Buffer

	if err := run([]string{"-t", "127.0.0.1", "-T", "200ms"}, &output); err != nil {
		t.Fatalf("run devolveu erro: %v", err)
	}

	expected := fmt.Sprintf("Portas:  %d", len(portscan.DefaultPorts()))
	if !strings.Contains(output.String(), expected) {
		t.Fatalf("cabeçalho não informa as portas padrão: %q", output.String())
	}
}

func TestRunExibeIPResolvidoETempoTotal(t *testing.T) {
	var output bytes.Buffer

	args := []string{"-t", "127.0.0.1", "-p", strconv.Itoa(portaFechada(t)), "-T", "200ms"}
	if err := run(args, &output); err != nil {
		t.Fatalf("run devolveu erro: %v", err)
	}

	text := output.String()
	if !strings.Contains(text, "IP:      127.0.0.1") {
		t.Errorf("saída não mostra o IP resolvido: %q", text)
	}
	if !strings.Contains(text, "Tempo total:") {
		t.Errorf("saída não mostra o tempo total: %q", text)
	}
}

// portaFechada devolve uma porta local que ninguém está escutando, para que a
// varredura de teste não dependa de nenhum serviço externo.
func portaFechada(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("não foi possível reservar a porta: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	return port
}
