package worker_test

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
	"github.com/joaofamello/port-scanner-academico/internal/worker"
)

func TestStartScanClassificaPortasEComPreservaOrdem(t *testing.T) {
	results := worker.StartScan("127.0.0.1", []int{80, 81, 82}, worker.PoolConfig{
		NumWorkers: 2,
		Timeout:    time.Second,
		Connect: func(ip string, port int, timeout time.Duration) (net.Conn, error) {
			switch port {
			case 80:
				return noopConnection{}, nil
			case 81:
				return nil, errors.New("connection refused")
			default:
				return nil, timeoutError{}
			}
		},
	})

	if len(results) != 3 {
		t.Fatalf("quantidade de resultados = %d, esperado 3", len(results))
	}
	if results[0].Port != 80 || results[0].Status != portscan.StatusOpen || !results[0].IsOpen {
		t.Fatalf("resultado da porta 80 incorreto: %+v", results[0])
	}
	if results[1].Port != 81 || results[1].Status != portscan.StatusClosed || results[1].IsOpen {
		t.Fatalf("resultado da porta 81 incorreto: %+v", results[1])
	}
	if results[2].Port != 82 || results[2].Status != portscan.StatusFiltered || !results[2].TimedOut {
		t.Fatalf("resultado da porta 82 incorreto: %+v", results[2])
	}
}

func TestStartScanRespeitaLimiteDeWorkers(t *testing.T) {
	var active int32
	var maximum int32

	results := worker.StartScan("127.0.0.1", []int{1, 2, 3, 4}, worker.PoolConfig{
		NumWorkers: 2,
		Connect: func(ip string, port int, timeout time.Duration) (net.Conn, error) {
			current := atomic.AddInt32(&active, 1)
			for {
				previous := atomic.LoadInt32(&maximum)
				if current <= previous || atomic.CompareAndSwapInt32(&maximum, previous, current) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			atomic.AddInt32(&active, -1)
			return nil, errors.New("connection refused")
		},
	})

	if len(results) != 4 {
		t.Fatalf("quantidade de resultados = %d, esperado 4", len(results))
	}
	if maximum > 2 {
		t.Fatalf("máximo de workers ativos = %d, esperado no máximo 2", maximum)
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type noopConnection struct{}

func (noopConnection) Read([]byte) (int, error)         { return 0, errors.New("not implemented") }
func (noopConnection) Write(data []byte) (int, error)   { return len(data), nil }
func (noopConnection) Close() error                     { return nil }
func (noopConnection) LocalAddr() net.Addr              { return nil }
func (noopConnection) RemoteAddr() net.Addr             { return nil }
func (noopConnection) SetDeadline(time.Time) error      { return nil }
func (noopConnection) SetReadDeadline(time.Time) error  { return nil }
func (noopConnection) SetWriteDeadline(time.Time) error { return nil }
