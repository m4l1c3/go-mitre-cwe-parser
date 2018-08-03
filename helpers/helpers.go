package helpers

import (
	"fmt"
	"os"
	"strings"
)

func TrimRandom(s string) string {
	return strings.Replace(s, "   ", "", -1)
}

func Trim(s string) string {
	return TrimRandom(strings.TrimSpace(s))
}

func WriteOutput(index string, data []byte) {
	outputFile, err := os.Create(fmt.Sprintf("./%s-%s", index, "output.json"))
	if err != nil {
		fmt.Printf("Error writing output: %s\n")
		return
	}
	defer outputFile.Close()

	var output = string(data)
	output = strings.Replace(output, "\n", "\n\n", -1)
	_, error := outputFile.WriteString(fmt.Sprintf("%s", output))
	if error != nil {
		fmt.Printf("Error writing file %s\n", err)
		return
	}
	outputFile.Sync()
}
