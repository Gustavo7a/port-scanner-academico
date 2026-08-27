package parser_test

import (
	"errors"
	"testing"

	"github.com/joaofamello/port-scanner-academico/internal/parser"
)

func TestResolveTargetComIP(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ip simples", "192.168.0.1", "192.168.0.1"},
		{"ip com porta", "8.8.8.8:80", "8.8.8.8"},
		{"ip dentro de url", "http://8.8.8.8/caminho?a=1", "8.8.8.8"},
		{"ip com espacos em volta", "  1.1.1.1  ", "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.ResolveTarget(tt.input)
			if err != nil {
				t.Fatalf("ResolveTarget(%q) devolveu erro inesperado: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ResolveTarget(%q) = %q, esperado %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveTargetErros(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"entrada vazia", "", parser.ErrEmptyTarget},
		{"apenas espacos", "   ", parser.ErrEmptyTarget},
		{"ip com octeto acima de 255", "999.1.1.1", parser.ErrInvalidTarget},
		{"ip com octeto a mais", "1.2.3.4.5", parser.ErrInvalidTarget},
		{"url sem host", "http://", parser.ErrInvalidTarget},
		{"ipv6", "::1", parser.ErrNoIPV4Address},
		{"ipv6 com porta", "[::1]:8080", parser.ErrNoIPV4Address},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.ResolveTarget(tt.input)
			if err == nil {
				t.Fatalf("ResolveTarget(%q) = %q, esperava um erro", tt.input, got)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ResolveTarget(%q) devolveu %v, esperava %v", tt.input, err, tt.wantErr)
			}
			if got != "" {
				t.Errorf("ResolveTarget(%q) devolveu %q junto com o erro, esperava string vazia", tt.input, got)
			}
		})
	}
}

func TestResolveTargetComDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("precisa de DNS")
	}

	got, err := parser.ResolveTarget("localhost")
	if err != nil {
		t.Fatalf("ResolveTarget(%q) devolveu erro: %v", "localhost", err)
	}
	if got != "127.0.0.1" {
		t.Errorf("ResolveTarget(%q) = %q, esperado 127.0.0.1", "localhost", got)
	}
}

func TestResolveTargetDominioInexistente(t *testing.T) {
	if testing.Short() {
		t.Skip("precisa de DNS")
	}

	if _, err := parser.ResolveTarget("alvo-que-nao-existe.invalid"); err == nil {
		t.Error("esperava erro para um domínio inexistente, mas a resolução teve sucesso")
	}
}
