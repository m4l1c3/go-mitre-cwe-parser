package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/m4l1c3/go-mitre-cwe-parser/helpers"
	"github.com/m4l1c3/go-mitre-cwe-parser/types"
	"github.com/m4l1c3/go-mitre-cwe-parser/validation"
)

//GetXML is a wrapper for go's built-in unmarshalling methods, this transforms raw XML into pre-defined struct
func GetXML(xmlData []byte, weaknesses *types.WeaknessCatalog) {
	error := xml.Unmarshal(xmlData, &weaknesses)

	if error != nil {
		fmt.Printf("Error unmarshalling: %s\n", error)
		return
	}
}

//GetJSON is a wrapper for go's built-in marshalling method for converting structs into pre-defined structs to JSON objects
func GetJSON(value interface{}) []byte {
	data, error := json.Marshal(value)

	if error != nil {
		fmt.Printf("Error marshalling to json: %s\n", error)
		return nil
	}

	return data
}

//AppendVulns takes a weakness and converts it into a Vulnerability object and appends it to a slice containing Vulnerabilities
func AppendVulns(vulns []types.Vulnerability, catalog string, weakness *types.Weakness) []types.Vulnerability {
	if validation.VulnerabilityIsValid(catalog, weakness) {
		rec := ""
		for _, mitigation := range weakness.MitigationStrategy.Mitigations {
			if validation.MitigationIsValid(&mitigation) {
				rec += fmt.Sprintf("%s", helpers.Trim(mitigation.Description))
			}
		}
		return append(vulns, types.Vulnerability{
			Title:           fmt.Sprintf("%s-%s: %s", catalog, weakness.ID, weakness.Name),
			Description:     helpers.Trim(weakness.Description),
			Source:          "Other",
			References:      fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", weakness.ID),
			Severity:        "Medium",
			Recommendations: rec,
		})

	}
	return nil
}

func main() {
	var fileName = "./fixtures/cwec_v3.0.xml"
	var vulns []types.Vulnerability
	xmlData, err := ioutil.ReadFile(fileName)

	if err != nil {
		fmt.Printf("Error reading XML data from file: %s, error: %s\n", fileName, err)
	}

	weaknesses := types.WeaknessCatalog{}
	GetXML(xmlData, &weaknesses)
	catalogName := weaknesses.CatalogName

	//Create our array of vulnerabilities
	for _, item := range weaknesses.Flaws.Findings {
		vulns = AppendVulns(vulns, catalogName, &item)
	}

	if len(vulns) > 0 {
		//Write each vulnerability to a JSON file
		for i, v := range vulns {
			helpers.WriteOutput(strconv.Itoa(i), GetJSON(&v))
		}
	}
}
