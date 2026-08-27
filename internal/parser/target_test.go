package parser

import (
	"errors"
	"testing"
)

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"ip puro", "192.168.0.1", "192.168.0.1"},
		{"ip com porta", "8.8.8.8:80", "8.8.8.8"},
		{"ip com espacos em volta", "  8.8.8.8  ", "8.8.8.8"},
		{"dominio", "google.com", "google.com"},
		{"dominio com espacos em volta", "  google.com  ", "google.com"},
		{"dominio com porta e caminho", "google.com:8080/busca", "google.com"},
		{"url http", "http://google.com/", "google.com"},
		{"url https com query e fragmento", "https://exemplo.com.br/a/b?x=1&y=2#frag", "exemplo.com.br"},
		{"url com outro protocolo", "ftp://arquivos.exemplo.com/pub", "arquivos.exemplo.com"},
		// Sem o atalho do ParseIP, o url.Parse leria "::1" como host ":" e porta "1".
		{"ipv6 sem colchetes", "::1", "::1"},
		{"ipv6 com colchetes e porta", "[::1]:8080", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractHost(tt.input)
			if err != nil {
				t.Fatalf("extractHost(%q) devolveu erro inesperado: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("extractHost(%q) = %q, esperado %q", tt.input, got, tt.want)
			}
		})
	}
}

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
			got, err := ResolveTarget(tt.input)
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
		{"entrada vazia", "", ErrEmptyTarget},
		{"apenas espacos", "   ", ErrEmptyTarget},
		// Só dígitos e pontos, então nem chega no DNS.
		{"ip com octeto acima de 255", "999.1.1.1", ErrInvalidTarget},
		{"ip com octeto a mais", "1.2.3.4.5", ErrInvalidTarget},
		{"url sem host", "http://", ErrInvalidTarget},
		{"ipv6", "::1", ErrNoIPV4Address},
		{"ipv6 com porta", "[::1]:8080", ErrNoIPV4Address},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveTarget(tt.input)
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

// O heurístico existe só para separar "IP digitado errado" de "domínio que não
// resolve", então basta cobrir os dois lados.
func TestLooksLikeIPV4(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"192.168.0.1", true},
		{"999.1.1.1", true},
		{"1.2.3.4.5", true},
		{"google.com", false},
		{"localhost", false},
		{"123", false},
		{"::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := looksLikeIPV4(tt.input); got != tt.want {
				t.Errorf("looksLikeIPV4(%q) = %v, esperado %v", tt.input, got, tt.want)
			}
		})
	}
}

// Os dois testes abaixo dependem do resolvedor do sistema. Rode com -short
// para pular, por exemplo em CI sem saída para a internet.

func TestResolveTargetComDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("precisa de DNS")
	}

	const alvo = "localhost"

	got, err := ResolveTarget(alvo)
	if err != nil {
		t.Fatalf("ResolveTarget(%q) devolveu erro: %v", alvo, err)
	}
	if got != "127.0.0.1" {
		t.Errorf("ResolveTarget(%q) = %q, esperado 127.0.0.1", alvo, got)
	}
}

func TestResolveTargetDominioInexistente(t *testing.T) {
	if testing.Short() {
		t.Skip("precisa de DNS")
	}

	// O TLD .invalid é reservado pela RFC 2606 e nunca resolve.
	if _, err := ResolveTarget("alvo-que-nao-existe.invalid"); err == nil {
		t.Error("esperava erro para um domínio inexistente, mas a resolução teve sucesso")
	}
}
