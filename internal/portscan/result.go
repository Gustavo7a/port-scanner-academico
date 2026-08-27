package portscan

// PortStatus representa o estado identificado durante a tentativa TCP.
type PortStatus string

const (
	StatusOpen     PortStatus = "open"
	StatusClosed   PortStatus = "closed"
	StatusFiltered PortStatus = "filtered"
)

// ScanResult representa o estado final de uma porta após a tentativa de conexão.
type ScanResult struct {
	Port     int
	IsOpen   bool
	Status   PortStatus
	TimedOut bool
	Banner   string
}
