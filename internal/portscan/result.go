package portscan

// ScanResult reprensenta o estado final de uma porta após a tentativa de conexão.
type ScanResult struct {
	Port   int
	IsOpen bool
	Banner string
}
