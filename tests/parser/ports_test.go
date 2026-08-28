package parser_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/joaofamello/port-scanner-academico/internal/parser"
)

func TestParsePortsEntradasValidas(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []int
	}{
		{"porta unica", "80", []int{80}},
		{"intervalo", "20-25", []int{20, 21, 22, 23, 24, 25}},
		{"intervalo de uma porta so", "80-80", []int{80}},
		{"lista", "80,443,8080", []int{80, 443, 8080}},
		{"lista com intervalo", "22,80,8000-8002", []int{22, 80, 8000, 8001, 8002}},
		{"varios intervalos", "20-22,80-81", []int{20, 21, 22, 80, 81}},
		{"remove duplicatas", "80,80,443", []int{80, 443}},
		{"remove duplicatas entre lista e intervalo", "80,79-81", []int{79, 80, 81}},
		{"ordena a saida", "443,22,80", []int{22, 80, 443}},
		{"ignora espacos", " 80 , 443 ", []int{80, 443}},
		{"ignora espacos dentro do intervalo", "20 - 22", []int{20, 21, 22}},
		{"limite inferior", "1", []int{1}},
		{"limite superior", "65535", []int{65535}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.ParsePorts(tt.input)
			if err != nil {
				t.Fatalf("ParsePorts(%q) devolveu erro inesperado: %v", tt.input, err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ParsePorts(%q) = %v, esperado %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParsePortsErros(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"entrada vazia", "", parser.ErrEmptyPorts},
		{"apenas espacos", "   ", parser.ErrEmptyPorts},
		{"texto no lugar do numero", "abc", parser.ErrInvalidPort},
		{"numero decimal", "80.5", parser.ErrInvalidPort},
		{"porta zero", "0", parser.ErrInvalidPort},
		{"porta acima do maximo", "65536", parser.ErrInvalidPort},
		{"item vazio na lista", "80,,443", parser.ErrInvalidPort},
		{"lista terminando em virgula", "80,", parser.ErrInvalidPort},
		{"intervalo sem inicio", "-25", parser.ErrInvalidPort},
		{"intervalo sem fim", "20-", parser.ErrInvalidPort},
		{"intervalo com porta invalida", "20-70000", parser.ErrInvalidPort},
		{"intervalo com tres limites", "1-2-3", parser.ErrInvalidRange},
		{"intervalo invertido", "25-20", parser.ErrInvalidRange},
		{"porta valida seguida de invalida", "80,abc", parser.ErrInvalidPort},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parser.ParsePorts(tt.input)
			if err == nil {
				t.Fatalf("ParsePorts(%q) = %v, esperava um erro", tt.input, got)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParsePorts(%q) devolveu %v, esperava %v", tt.input, err, tt.wantErr)
			}
			if got != nil {
				t.Errorf("ParsePorts(%q) devolveu %v junto com o erro, esperava nil", tt.input, got)
			}
		})
	}
}

func TestParsePortsIntervaloCompletoNaoEstoura(t *testing.T) {
	got, err := parser.ParsePorts("1-65535")
	if err != nil {
		t.Fatalf("ParsePorts do intervalo completo devolveu erro: %v", err)
	}
	if len(got) != 65535 {
		t.Fatalf("quantidade de portas = %d, esperado 65535", len(got))
	}
	if got[0] != 1 || got[len(got)-1] != 65535 {
		t.Errorf("limites do intervalo = %d e %d, esperado 1 e 65535", got[0], got[len(got)-1])
	}
}
