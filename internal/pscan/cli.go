package pscan

import (
	"errors"
	"flag"
	"fmt"
	"io"
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

const (
	appName        = "pscan"
	appVersion     = "1.0"
	defaultWorkers = 100
	defaultTimeout = 2 * time.Second
)

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

var (
	ErrMissingTarget  = errors.New("informe o alvo com -t ou --target")
	ErrInvalidWorkers = errors.New("a quantidade de workers deve ser maior que zero")
	ErrInvalidTimeout = errors.New("o timeout deve ser maior que zero")
)

type options struct {
	target  string
	ports   string
	workers int
	timeout time.Duration
	banner  bool
}

// Run executa a CLI com os argumentos recebidos e escreve o relatório em out.
func Run(args []string, out io.Writer) error {
	printLogo(out)

	flags := flag.NewFlagSet(appName, flag.ContinueOnError)
	flags.SetOutput(out)

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
	PrintResults(out, results, time.Since(start), opts.banner)

	return nil
}

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

func printLogo(out io.Writer) {
	for _, line := range logo {
		fmt.Fprintln(out, line)
	}
	fmt.Fprintf(out, "\nPScan v%s - varredura TCP connect sobre IPv4\n\n", appVersion)
}

func commandName() string {
	if runtime.GOOS == "windows" {
		return `.\` + appName + ".exe"
	}
	return "./" + appName
}

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

func printHeader(out io.Writer, opts options, ip string, totalPorts int) {
	fmt.Fprintf(out, "Alvo:    %s\n", opts.target)
	fmt.Fprintf(out, "IP:      %s\n", ip)
	fmt.Fprintf(out, "Portas:  %d | Workers: %d | Timeout: %s | Banner: %s\n\n",
		totalPorts, opts.workers, opts.timeout, statusLabel(opts.banner))
}

// PrintResults imprime a tabela de portas abertas e o resumo da varredura.
func PrintResults(out io.Writer, results []portscan.ScanResult, elapsed time.Duration, showBanner bool) {
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
				line += "\t" + CleanBanner(result.Banner)
			}
			fmt.Fprintln(table, line)
		}
		table.Flush()
	}

	fmt.Fprintf(out, "\n%d portas verificadas: %d abertas, %d fechadas, %d filtradas\n",
		len(results), open, closed, filtered)
	fmt.Fprintf(out, "Tempo total: %s\n", elapsed.Round(time.Millisecond))
}

// CleanBanner normaliza e limita um banner para uso na tabela de resultados.
func CleanBanner(banner string) string {
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

func statusLabel(enabled bool) string {
	if enabled {
		return "ativado"
	}
	return "desativado"
}
