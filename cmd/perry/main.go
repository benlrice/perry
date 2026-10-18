package main

import (
	"os"

	"github.com/benlrice/perry/internal/perry"
)

func main() {
	os.Exit(perry.Main(os.Args[1:]))
}
