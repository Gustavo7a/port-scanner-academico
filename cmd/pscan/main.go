package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/joaofamello/port-scanner-academico/internal/parser"
	"github.com/joaofamello/port-scanner-academico/internal/portscan"
	"github.com/joaofamello/port-scanner-academico/internal/worker"
)

// Identificação da ferramenta.
const (
	appName    = "pscan"
	appVersion = "1.0"
)

// Valores aplicados quando o usuário não informa a opção.
const (
	defaultWorkers = 100
	defaultTimeout = 2 * time.Second
)

var logo = []string{
	" ____   ____",
	"|  _ \\ / ___|   ___    __ _  _ __",
	"| |_) |\\___ \\  / __|  / _` || '_ \\",
	"|  __/  ___) || (__  | (_| || | | |",
	"|_|    |____/  \\___|  \\__,_||_| |_|",
}

// Erros de uso da linha de comando.
var (
	ErrMissingTarget  = errors.New("informe o alvo com -target")
	ErrInvalidWorkers = errors.New("a quantidade de workers deve ser maior que zero")
	ErrInvalidTimeout = errors.New("o timeout deve ser maior que zero")
)

// options guarda os valores lidos da linha de comando.
type options struct {
	target  string
	ports   string
	workers int
	timeout time.Duration
	banner  bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "erro: %v\n", err)
		os.Exit(1)
	}
}

// run concentra a execução da CLI: lê os argumentos, valida, dispara a varredura
// e escreve o relatório. Recebe args e writer para poder ser testada sem processo.
func run(args []string, out io.Writer) error {
	printLogo(out)

	flags := flag.NewFlagSet(appName, flag.ContinueOnError)
	flags.SetOutput(out)

	var opts options
	flags.StringVar(&opts.target, "target", "", "URL, domínio ou IP que será varrido (obrigatório)")
	flags.StringVar(&opts.ports, "ports", "", "portas a varrer: \"80\", \"20-25\" ou \"22,80,8000-8010\" (padrão: portas comuns)")
	flags.IntVar(&opts.workers, "workers", defaultWorkers, "quantidade de conexões simultâneas")
	flags.DurationVar(&opts.timeout, "timeout", defaultTimeout, "tempo máximo de espera por porta (ex: 500ms, 2s)")
	flags.BoolVar(&opts.banner, "banner", false, "tenta ler o banner das portas abertas")
	flags.Usage = func() { printUsage(out, flags) }

	if err := flags.Parse(args); err != nil {
		// -h e -help não são falhas: o texto de ajuda já foi impresso.
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	ports, err := resolveOptions(opts)
	if err != nil {
		flags.Usage()
		return err
	}

	ip, err := parser.ResolveTarget(opts.target)
	if err != nil {
		return err
	}

	printHeader(out, opts, ip, len(ports))

	start := time.Now()
	results := worker.StartScan(ip, ports, worker.PoolConfig{
		NumWorkers:    opts.workers,
		Timeout:       opts.timeout,
		CaptureBanner: opts.banner,
	})
	elapsed := time.Since(start)

	printResults(out, results, elapsed, opts.banner)

	return nil
}

// resolveOptions valida os parâmetros obrigatórios e devolve a lista de portas
// que será varrida. As checagens vêm antes da resolução do alvo para não gastar
// uma consulta de DNS quando a linha de comando já está errada.
func resolveOptions(opts options) ([]int, error) {
	if strings.TrimSpace(opts.target) == "" {
		return nil, ErrMissingTarget
	}

	if opts.workers <= 0 {
		return nil, fmt.Errorf("%d workers: %w", opts.workers, ErrInvalidWorkers)
	}

	if opts.timeout <= 0 {
		return nil, fmt.Errorf("timeout de %s: %w", opts.timeout, ErrInvalidTimeout)
	}

	if strings.TrimSpace(opts.ports) == "" {
		return portscan.DefaultPorts(), nil
	}

	return parser.ParsePorts(opts.ports)
}

// printLogo escreve a assinatura da ferramenta e a versão.
func printLogo(out io.Writer) {
	for _, line := range logo {
		fmt.Fprintln(out, line)
	}
	fmt.Fprintf(out, "\nPScan v%s - varredura TCP connect sobre IPv4\n\n", appVersion)
}

// commandName monta o nome do executável do jeito que ele precisa ser digitado
// no terminal. No Windows o prefixo ".\" é obrigatório porque o PowerShell não
// procura programas no diretório atual.
func commandName() string {
	if runtime.GOOS == "windows" {
		return `.\` + appName + ".exe"
	}
	return "./" + appName
}

// printUsage descreve o funcionamento da ferramenta.
func printUsage(out io.Writer, flags *flag.FlagSet) {
	command := commandName()

	fmt.Fprintf(out, "Uso:\n  %s -target <alvo> [opções]\n", command)
	fmt.Fprintln(out, "\nOpções:")
	flags.PrintDefaults()
	fmt.Fprintln(out, "\nExemplos:")
	fmt.Fprintf(out, "  %s -target scanme.nmap.org\n", command)
	fmt.Fprintf(out, "  %s -target 192.168.0.1 -ports 22,80,8000-8010\n", command)
	fmt.Fprintf(out, "  %s -target https://exemplo.com -ports 1-1024 -workers 200 -timeout 500ms -banner\n", command)
}

// printHeader mostra o que será varrido, incluindo o IP resolvido a partir do alvo.
func printHeader(out io.Writer, opts options, ip string, totalPorts int) {
	fmt.Fprintf(out, "Alvo:    %s\n", opts.target)
	fmt.Fprintf(out, "IP:      %s\n", ip)
	fmt.Fprintf(out, "Portas:  %d | Workers: %d | Timeout: %s | Banner: %s\n\n",
		totalPorts, opts.workers, opts.timeout, statusLabel(opts.banner))
}

// printResults imprime a tabela de portas abertas, o resumo e o tempo de execução.
func printResults(out io.Writer, results []portscan.ScanResult, elapsed time.Duration, showBanner bool) {
	var open, closed, filtered int
	for _, result := range results {
		switch result.Status {
		case portscan.StatusOpen:
			open++
		case portscan.StatusFiltered:
			filtered++
		default:
			closed++
		}
	}

	if open == 0 {
		fmt.Fprintln(out, "Nenhuma porta aberta encontrada.")
	} else {
		table := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)

		header := "PORTA\tESTADO\tSERVIÇO"
		if showBanner {
			header += "\tBANNER"
		}
		fmt.Fprintln(table, header)

		for _, result := range results {
			if result.Status != portscan.StatusOpen {
				continue
			}

			line := fmt.Sprintf("%d\t%s\t%s", result.Port, result.Status, portscan.ServiceName(result.Port))
			if showBanner {
				line += "\t" + cleanBanner(result.Banner)
			}
			fmt.Fprintln(table, line)
		}

		table.Flush()
	}

	fmt.Fprintf(out, "\n%d portas verificadas: %d abertas, %d fechadas, %d filtradas\n",
		len(results), open, closed, filtered)
	fmt.Fprintf(out, "Tempo total: %s\n", elapsed.Round(time.Millisecond))
}

// cleanBanner deixa o banner em uma única linha para não quebrar o alinhamento da tabela.
func cleanBanner(banner string) string {
	banner = strings.TrimSpace(banner)
	if banner == "" {
		return "-"
	}

	replacer := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ")

	return strings.TrimSpace(replacer.Replace(banner))
}

// statusLabel traduz uma opção booleana para o relatório.
func statusLabel(enabled bool) string {
	if enabled {
		return "ativado"
	}
	return "desativado"
}
