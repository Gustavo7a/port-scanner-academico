package parser

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/joaofamello/port-scanner-academico/internal/portscan"
)

// Erros que podem ser retornados pela função ParsePorts.
var (
	ErrEmptyPorts   = errors.New("nenhuma porta informada")
	ErrInvalidPort  = errors.New("porta inválida")
	ErrInvalidRange = errors.New("intervalo de portas inválido")
)

// ParsePorts interpreta a seleção de portas informada pelo usuário.
// Aceita porta única ("80"), intervalo ("20-25"), lista ("80,443")
// e a combinação de listas com intervalos ("22,80,8000-8010").
// O retorno vem ordenado e sem duplicatas.
func ParsePorts(input string) ([]int, error) {
	text := strings.TrimSpace(input)
	if text == "" {
		return nil, ErrEmptyPorts
	}

	unique := make(map[int]struct{})

	for _, token := range strings.Split(text, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			return nil, fmt.Errorf("item vazio em %q: %w", input, ErrInvalidPort)
		}

		if strings.Contains(token, "-") {
			start, end, err := parseRange(token)
			if err != nil {
				return nil, err
			}
			for port := start; port <= end; port++ {
				unique[port] = struct{}{}
			}
			continue
		}

		port, err := parsePort(token)
		if err != nil {
			return nil, err
		}
		unique[port] = struct{}{}
	}

	ports := make([]int, 0, len(unique))
	for port := range unique {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	return ports, nil
}

// parsePort converte um token em uma porta TCP dentro do intervalo permitido.
func parsePort(token string) (int, error) {
	port, err := strconv.Atoi(token)
	if err != nil {
		return 0, fmt.Errorf("%q não é um número inteiro válido: %w", token, ErrInvalidPort)
	}

	if !portscan.IsValidPort(port) {
		return 0, fmt.Errorf("a porta %d está fora do intervalo %d-%d: %w",
			port, portscan.MinPort, portscan.MaxPort, ErrInvalidPort)
	}

	return port, nil
}

// parseRange converte um token no formato "inicio-fim" nos dois limites do intervalo.
func parseRange(token string) (int, int, error) {
	limits := strings.Split(token, "-")
	if len(limits) != 2 {
		return 0, 0, fmt.Errorf("%q não segue o formato inicio-fim: %w", token, ErrInvalidRange)
	}

	start, err := parsePort(strings.TrimSpace(limits[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("início do intervalo inválido em %q: %w", token, err)
	}

	end, err := parsePort(strings.TrimSpace(limits[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("fim do intervalo inválido em %q: %w", token, err)
	}

	if start > end {
		return 0, 0, fmt.Errorf("%q começa depois de terminar: %w", token, ErrInvalidRange)
	}

	return start, end, nil
}
