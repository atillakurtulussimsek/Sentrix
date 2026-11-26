package main

import (
	"fmt"

	"github.com/atillakurtulussimsek/Sentrix/internal/version"
)

func main() {
	fmt.Println("sentrix-server", version.String())
}
