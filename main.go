package main

import (
	"fmt"
	"strings"

	xj "github.com/basgys/goxml2json"
)

func main() {
	xml := strings.NewReader("")

	json, err := xj.Convert(xml)
	if err != nil {
		fmt.Printf("Error converting xml to json: %s\n", err)
	}

	fmt.Printf("JSON output: %s\n", json)
}
