package pscan_test

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
	"github.com/joaofamello/port-scanner-academico/internal/pscan"
)

func TestPrintResultsOrdenaPortasAbertasEExibeResumo(t *testing.T) {
	results := []portscan.ScanResult{
		{Port: 443, Status: portscan.StatusOpen, IsOpen: true, Banner: "HTTPS"},
		{Port: 22, Status: portscan.StatusClosed},
		{Port: 80, Status: portscan.StatusOpen, IsOpen: true, Banner: "HTTP"},
		{Port: 8080, Status: portscan.StatusFiltered, TimedOut: true},
	}
	originalFirstPort := results[0].Port
	var output bytes.Buffer

	pscan.PrintResults(&output, results, 1250*time.Millisecond, true)

	text := output.String()
	firstOpen := strings.Index(text, "80")
	secondOpen := strings.Index(text, "443")
	if firstOpen == -1 || secondOpen == -1 || firstOpen >= secondOpen {
		t.Fatalf("portas abertas fora de ordem na saída: %q", text)
	}
	if strings.Contains(text, "22\t") || strings.Contains(text, "8080\t") {
		t.Fatalf("portas fechada/filtrada apareceram na tabela: %q", text)
	}
	if !strings.Contains(text, "4 portas verificadas: 2 abertas, 1 fechadas, 1 filtradas") {
		t.Fatalf("resumo incorreto: %q", text)
	}
	if !strings.Contains(text, "Tempo total: 1.25s") {
		t.Fatalf("duração ausente ou incorreta: %q", text)
	}
	if results[0].Port != originalFirstPort {
		t.Fatalf("PrintResults modificou a ordem recebida: %+v", results)
	}
}

func TestCleanBannerNormalizaETunca(t *testing.T) {
	banner := "  linha inicial\r\nlinha intermediária\t" + strings.Repeat("x", 130) + "  "

	cleaned := pscan.CleanBanner(banner)

	if utf8.RuneCountInString(cleaned) != 120 {
		t.Fatalf("tamanho do banner = %d, esperado 120: %q", utf8.RuneCountInString(cleaned), cleaned)
	}
	if !strings.HasSuffix(cleaned, "...") {
		t.Fatalf("banner truncado sem marcador: %q", cleaned)
	}
	if strings.ContainsAny(cleaned, "\r\n\t") {
		t.Fatalf("banner ainda contém quebra ou tabulação: %q", cleaned)
	}
}

func TestPrintResultsSemPortasAbertasMantemResumo(t *testing.T) {
	results := []portscan.ScanResult{
		{Port: 443, Status: portscan.StatusClosed},
		{Port: 80, Status: portscan.StatusFiltered},
	}
	var output bytes.Buffer

	pscan.PrintResults(&output, results, 2*time.Millisecond, false)

	text := output.String()
	if !strings.Contains(text, "Nenhuma porta aberta encontrada.") {
		t.Fatalf("mensagem de ausência de portas abertas não encontrada: %q", text)
	}
	if !strings.Contains(text, "2 portas verificadas: 0 abertas, 1 fechadas, 1 filtradas") {
		t.Fatalf("resumo incorreto: %q", text)
	}
}
