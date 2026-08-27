package parser

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Erros que podem ser retornados pela função ResolveTarget.
var (
	ErrEmptyTarget   = errors.New("nenhum alvo informado")
	ErrInvalidTarget = errors.New("o alvo informado é inválido")
	ErrNoIPV4Address = errors.New("o alvo não possui um endereço IPV4")
)

// ResolveTarget recebe uma URL, domínio ou endereço IP e retorna apenas o endereço IPv4 limpo.
func ResolveTarget(input string) (string, error) {
	host, err := extractHost(input)
	if err != nil {
		return "", err
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.To4() != nil {
			return ip.String(), nil
		}
		return "", fmt.Errorf("%q é IPv6 e este scanner trabalha apenas com IPv4: %w", host, ErrNoIPV4Address)
	}

	if looksLikeIPV4(host) {
		return "", fmt.Errorf("%q não é um endereço IPv4 válido: %w", host, ErrInvalidTarget)
	}

	addresses, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("não foi possível resolver o domínio %q: %w", host, err)
	}

	for _, address := range addresses {
		if address.To4() != nil {
			return address.String(), nil
		}
	}

	return "", fmt.Errorf("o domínio %q respondeu apenas com IPv6: %w", host, ErrNoIPV4Address)
}

// extractHost Remove a porta, caminho, e os parâmetros de entrada, retornado apenas o host (domínio ou IP).
func extractHost(input string) (string, error) {
	text := strings.TrimSpace(input)

	if text == "" {
		return "", ErrEmptyTarget
	}

	if net.ParseIP(text) != nil {
		return text, nil
	}

	if !strings.Contains(text, "://") {
		text = "//" + text
	}

	parsed, err := url.Parse(text)
	if err != nil {
		return "", fmt.Errorf("não foi possível interpretar %q: %w", input, ErrInvalidTarget)
	}

	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("não foi encontrado um host em %q: %w", input, ErrInvalidTarget)
	}

	return host, nil
}

// looksLikeIPV4 verifica se a string fornecida parece ser um endereço IPv4.
func looksLikeIPV4(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	for _, character := range host {
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
