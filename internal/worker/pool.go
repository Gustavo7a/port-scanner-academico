package worker

import (
	"time"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
)

// PoolConfig define os limites de processamento da nossa ferramenta.
type PoolConfig struct {
	NumWorkers int
	Timeout    time.Duration
}

// StartScan recebe o IP, a lista de portas e a configuração, iniciando as goroutines.
// Retorna uma lista de resultados contendo as portas que responderam.
func StartScan(ip string, ports []int, config PoolConfig) []portscan.ScanResult {
	return []portscan.ScanResult{}
}
