package main

import (
	"fmt"
	"io/ioutil"
	"strings"

	xj "github.com/basgys/goxml2json"
)

type VulnerabilityWriteup struct {
	Description string
	Resources   string
	URL         string
	Title       string
	Severity    string
}

func main() {
	var fileName = "./fixtures/1000.xml"
	xmlData, err := ioutil.ReadFile(fileName)

	if err != nil {
		fmt.Printf("Error reading XML data from file: %s, error: %s\n", fileName, err)
	}

	xml := strings.NewReader(string(xmlData))

	json, err := xj.Convert(xml)
	if err != nil {
		fmt.Printf("Error converting xml to json: %s\n", err)
	}

	fmt.Printf("JSON output: %s\n", json)
}
