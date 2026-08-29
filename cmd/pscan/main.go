package main

import (
	"fmt"
	"os"

	"github.com/joaofamello/port-scanner-academico/internal/pscan"
)

func main() {
	if err := pscan.Run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "erro: %v\n", err)
		os.Exit(1)
	}
}
