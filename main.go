package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
)

type WeaknessCatalog struct {
	XMLName     xml.Name `xml:"Weakness_Catalog"`
	CatalogName string   `xml:"Name,attr"`
	Flaws       Weaknesses
}

type Weaknesses struct {
	XMLName  xml.Name   `xml:"Weaknesses"`
	Findings []Weakness `xml:"Weakness"`
}

type Weakness struct {
	XMLName            xml.Name `xml:"Weakness"`
	ID                 string   `xml:"ID,attr"`
	Name               string   `xml:"Name,attr"`
	Description        string   `xml:"Description"`
	MitigationStrategy PotentialMitigations
}

type PotentialMitigations struct {
	XMLName     xml.Name     `xml:"Potential_Mitigations"`
	Mitigations []Mitigation `xml:"Mitigation"`
}

type Mitigation struct {
	XMLName     xml.Name `xml:"Mitigation"`
	Description string   `xml:"Description"`
}

func GetXML(xmlData []byte, weaknesses *WeaknessCatalog) {
	error := xml.Unmarshal(xmlData, &weaknesses)

	if error != nil {
		fmt.Printf("Error unmarshalling: %s\n", error)
		return
	}
}

func GetJSON(weaknesses WeaknessCatalog) []byte {
	data, error := json.Marshal(weaknesses)

	if error != nil {
		fmt.Printf("Error marshalling to json: %s\n", error)
		return nil
	}

	return data
}

func WriteOutput(data []byte) bool {
	outputFile, err := os.Create("./output.json")
	if err != nil {
		fmt.Printf("Error writing output: %s\n")
		return false
	}
	defer outputFile.Close()

	write, err := outputFile.WriteString(fmt.Sprintf("%s", string(data)))
	if err != nil {
		fmt.Printf("Error writing file %s\n", err)
		return false
	}
	if write > 0 {
		fmt.Printf("Succesfully wrote output to output.json")
	}
	outputFile.Sync()
	return true
}

func main() {
	var fileName = "./fixtures/cwec_v3.0.xml"
	xmlData, err := ioutil.ReadFile(fileName)

	if err != nil {
		fmt.Printf("Error reading XML data from file: %s, error: %s\n", fileName, err)
	}

	weaknesses := WeaknessCatalog{}
	GetXML(xmlData, &weaknesses)
	data := GetJSON(weaknesses)

	if data != nil {
		WriteOutput(data)
	}
}
