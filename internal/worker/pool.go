package worker

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
)

// PoolConfig define os limites de processamento da nossa ferramenta.
type PoolConfig struct {
	NumWorkers int
	Timeout    time.Duration
	Connect    func(string, int, time.Duration) (net.Conn, error)
}

const defaultNumWorkers = 1

// StartScan recebe o IP, a lista de portas e a configuração, iniciando as goroutines.
// Retorna um resultado para cada porta, preservando a ordem de entrada.
func StartScan(ip string, ports []int, config PoolConfig) []portscan.ScanResult {
	results := make([]portscan.ScanResult, len(ports))
	if len(ports) == 0 {
		return results
	}

	numWorkers := config.NumWorkers
	if numWorkers <= 0 {
		numWorkers = defaultNumWorkers
	}
	if numWorkers > len(ports) {
		numWorkers = len(ports)
	}
	dial := config.Connect
	if dial == nil {
		dial = portscan.Connect
	}

	jobs := make(chan int)
	type scanResult struct {
		index  int
		result portscan.ScanResult
	}
	completed := make(chan scanResult)
	var workersDone sync.WaitGroup
	workersDone.Add(numWorkers)

	for workerID := 0; workerID < numWorkers; workerID++ {
		go func() {
			defer workersDone.Done()
			for index := range jobs {
				completed <- scanResult{
					index:  index,
					result: scanPort(dial, ip, ports[index], config.Timeout),
				}
			}
		}()
	}

	go func() {
		for index := range ports {
			jobs <- index
		}
		close(jobs)
		workersDone.Wait()
		close(completed)
	}()

	for result := range completed {
		results[result.index] = result.result
	}

	return results
}

func scanPort(dial func(string, int, time.Duration) (net.Conn, error), ip string, port int, timeout time.Duration) portscan.ScanResult {
	result := portscan.ScanResult{Port: port, Status: portscan.StatusClosed}

	connection, err := dial(ip, port, timeout)
	if err == nil {
		result.IsOpen = true
		result.Status = portscan.StatusOpen
		connection.Close()
		return result
	}

	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		result.Status = portscan.StatusFiltered
		result.TimedOut = true
	}

	return result
}
