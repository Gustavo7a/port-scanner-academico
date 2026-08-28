package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strconv"
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

// Descrição de cada opção. Ficam em constantes porque são usadas duas vezes:
// no registro da flag longa e no registro do atalho de uma letra.
const (
	usageTarget  = "URL, domínio ou IP que será varrido (obrigatório)"
	usagePorts   = "portas a varrer: \"80\", \"20-25\" ou \"22,80,8000-8010\" (padrão: portas comuns)"
	usageWorkers = "quantidade de conexões simultâneas"
	usageTimeout = "tempo máximo de espera por porta (ex: 500ms, 2s)"
	usageBanner  = "tenta ler o banner das portas abertas"
)

var logo = []string{
	" ____   ____",
	"|  _ \\ / ___|   ___    __ _  _ __",
	"| |_) |\\___ \\  / __|  / _` || '_ \\",
	"|  __/  ___) || (__  | (_| || | | |",
	"|_|    |____/  \\___|  \\__,_||_| |_|",
}

// optionUsage descreve uma opção no texto de ajuda, reunindo o atalho de uma
// letra e a forma longa em uma única linha.
type optionUsage struct {
	short        string
	long         string
	valueType    string
	description  string
	defaultValue string
}

var optionsUsage = []optionUsage{
	{"-t", "--target", "string", usageTarget, ""},
	{"-p", "--ports", "string", usagePorts, ""},
	{"-w", "--workers", "int", usageWorkers, strconv.Itoa(defaultWorkers)},
	{"-T", "--timeout", "duration", usageTimeout, defaultTimeout.String()},
	{"-b", "--banner", "", usageBanner, ""},
	{"-h", "--help", "", "exibe esta ajuda", ""},
}

// Erros de uso da linha de comando.
var (
	ErrMissingTarget  = errors.New("informe o alvo com -t ou --target")
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

	// Cada opção é registrada duas vezes, na forma longa e no atalho de uma letra,
	// apontando para o mesmo campo. As duas grafias preenchem o mesmo valor.
	var opts options
	flags.StringVar(&opts.target, "target", "", usageTarget)
	flags.StringVar(&opts.target, "t", "", usageTarget)
	flags.StringVar(&opts.ports, "ports", "", usagePorts)
	flags.StringVar(&opts.ports, "p", "", usagePorts)
	flags.IntVar(&opts.workers, "workers", defaultWorkers, usageWorkers)
	flags.IntVar(&opts.workers, "w", defaultWorkers, usageWorkers)
	flags.DurationVar(&opts.timeout, "timeout", defaultTimeout, usageTimeout)
	flags.DurationVar(&opts.timeout, "T", defaultTimeout, usageTimeout)
	flags.BoolVar(&opts.banner, "banner", false, usageBanner)
	flags.BoolVar(&opts.banner, "b", false, usageBanner)
	flags.Usage = func() { printUsage(out) }

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

// printUsage descreve o funcionamento da ferramenta. A listagem é montada à mão
// em vez de usar flags.PrintDefaults porque o pacote flag imprimiria o atalho e a
// forma longa como se fossem duas opções diferentes.
func printUsage(out io.Writer) {
	command := commandName()

	fmt.Fprintf(out, "Uso:\n  %s --target <alvo> [opções]\n", command)

	fmt.Fprintln(out, "\nOpções:")
	table := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	for _, option := range optionsUsage {
		description := option.description
		if option.defaultValue != "" {
			description = fmt.Sprintf("%s (padrão: %s)", description, option.defaultValue)
		}
		fmt.Fprintf(table, "  %s, %s\t%s\t%s\n", option.short, option.long, option.valueType, description)
	}
	table.Flush()

	fmt.Fprintln(out, "\nExemplos:")
	fmt.Fprintf(out, "  %s --target scanme.nmap.org\n", command)
	fmt.Fprintf(out, "  %s -t 192.168.0.1 -p 22,80,8000-8010\n", command)
	fmt.Fprintf(out, "  %s --target https://exemplo.com --ports 1-1024 --workers 200 --timeout 500ms --banner\n", command)
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

	orderedResults := append([]portscan.ScanResult(nil), results...)
	sort.SliceStable(orderedResults, func(i, j int) bool {
		return orderedResults[i].Port < orderedResults[j].Port
	})

	if open == 0 {
		fmt.Fprintln(out, "Nenhuma porta aberta encontrada.")
	} else {
		table := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)

		header := "PORTA\tESTADO\tSERVIÇO"
		if showBanner {
			header += "\tBANNER"
		}
		fmt.Fprintln(table, header)

		for _, result := range orderedResults {
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
	const maxBannerLength = 120
	const truncationSuffix = "..."

	banner = strings.TrimSpace(banner)
	if banner == "" {
		return "-"
	}

	replacer := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ")

	banner = strings.TrimSpace(replacer.Replace(banner))
	bannerRunes := []rune(banner)
	if len(bannerRunes) <= maxBannerLength {
		return banner
	}

	return string(bannerRunes[:maxBannerLength-len([]rune(truncationSuffix))]) + truncationSuffix
}

// statusLabel traduz uma opção booleana para o relatório.
func statusLabel(enabled bool) string {
	if enabled {
		return "ativado"
	}
	return "desativado"
}
