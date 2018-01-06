package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/m4l1c3/go-mitre-cwe-parser/helpers"
	"github.com/m4l1c3/go-mitre-cwe-parser/types"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

//type WeaknessCatalog struct {
//    XMLName     xml.Name `xml:"Weakness_Catalog"`
//    CatalogName string   `xml:"Name,attr"`
//    Flaws       Weaknesses
//}

//type Weaknesses struct {
//    XMLName  xml.Name   `xml:"Weaknesses"`
//    Findings []Weakness `xml:"Weakness"`
//}

//type Weakness struct {
//    XMLName            xml.Name `xml:"Weakness"`
//    ID                 string   `xml:"ID,attr"`
//    Name               string   `xml:"Name,attr"`
//    Description        string   `xml:"Description"`
//    MitigationStrategy PotentialMitigations
//}

//type PotentialMitigations struct {
//    XMLName     xml.Name     `xml:"Potential_Mitigations"`
//    Mitigations []Mitigation `xml:"Mitigation"`
//}

//type Mitigation struct {
//    XMLName     xml.Name `xml:"Mitigation"`
//    Description string   `xml:"Description"`
//}

//type Vulnerability struct {
//    Description     string `json:"description"`
//    Title           string `json:"title"`
//    Source          string `json:"source"`
//    References      string `json:"references"`
//    Recommendations string `json:"recommendations"`
//    Severity        string `json:"severity"`
//}

//func Trim(s string) string {
//    return TrimRandom(strings.TrimSpace(s))
//}

func GetXML(xmlData []byte, weaknesses *WeaknessCatalog) {
	error := xml.Unmarshal(xmlData, &weaknesses)

	if error != nil {
		fmt.Printf("Error unmarshalling: %s\n", error)
		return
	}
}

func GetJSON(value interface{}) []byte {
	data, error := json.Marshal(value)

	if error != nil {
		fmt.Printf("Error marshalling to json: %s\n", error)
		return nil
	}

	return data
}

func WriteOutput(index string, data []byte) bool {
	outputFile, err := os.Create(fmt.Sprintf("./%s-%s", index, "output.json"))
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

func VulnerabilityIsValid(catalog string, weakness *Weakness) bool {
	return WeaknessIsValid(weakness) && CatalogIsValid(catalog)
}

func WeaknessIsValid(weakness *Weakness) bool {
	return (weakness.ID != "" && weakness.Description != "" &&
		weakness.Name != "")
	//len(weakness.MitigationStrategy.Mitigations) > 0)
}

func MitigationIsValid(mitigation *Mitigation) bool {
	return mitigation != nil && mitigation.Description != ""
}

func CatalogIsValid(catalog string) bool {
	return catalog != ""
}

//func TrimRandom(s string) string {
//    return strings.Replace(s, "   ", "", -1)
//}

func AppendVulns(vulns []Vulnerability, catalog string, weakness *Weakness) []Vulnerability {
	if CatalogIsValid(catalog) && WeaknessIsValid(weakness) {
		rec := ""
		for _, mitigation := range weakness.MitigationStrategy.Mitigations {
			if MitigationIsValid(&mitigation) {
				rec += fmt.Sprintf("%s", Trim(mitigation.Description))
			}
		}
		return append(vulns, Vulnerability{
			Title:           fmt.Sprintf("%s-%s: %s", catalog, weakness.ID, weakness.Name),
			Description:     Trim(weakness.Description),
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
	xmlData, err := ioutil.ReadFile(fileName)

	if err != nil {
		fmt.Printf("Error reading XML data from file: %s, error: %s\n", fileName, err)
	}

	weaknesses := WeaknessCatalog{}
	GetXML(xmlData, &weaknesses)
	// data := GetWeaknessesJSON(weaknesses)

	catalogName := weaknesses.CatalogName
	var vulns []Vulnerability

	for _, item := range weaknesses.Flaws.Findings {
		// fmt.Printf("Index: %d, Item: %s\n", index, item)
		vulns = AppendVulns(vulns, catalogName, &item)
	}
	if len(vulns) > 0 {
		for i, v := range vulns {
			data := GetJSON(&v)
			WriteOutput(strconv.Itoa(i), data)
		}
	}

	// 	WriteOutput(data)
	// }
}
