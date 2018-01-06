package helpers

import (
	"fmt"
	"os"
)

func WriteOutput(index string, data []byte) {
	outputFile, err := os.Create(fmt.Sprintf("./%s-%s", index, "output.json"))
	if err != nil {
		fmt.Printf("Error writing output: %s\n")
		return
	}
	defer outputFile.Close()

	_, error := outputFile.WriteString(fmt.Sprintf("%s", string(data)))
	if error != nil {
		fmt.Printf("Error writing file %s\n", err)
		return
	}
	outputFile.Sync()
}
