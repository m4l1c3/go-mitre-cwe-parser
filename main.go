package main

import (
	//"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
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

type MitigationDescription struct {
	XMLName      xml.Name `xml:"Description"`
	Descriptions []string `xml:"xhtml:p,innerxml"`
}

type VulnerabilityWriteup struct {
	Description string
	Resources   string
	URL         string
	Title       string
	Severity    string
}

//func CreateVulnerability() *VulnerabilityWriteup {

//}

func main() {
	//vulnerabilities := make([]VulnerabilityWriteup, 0)
	var fileName = "./fixtures/cwec_v3.0.xml"
	xmlData, err := ioutil.ReadFile(fileName)

	if err != nil {
		fmt.Printf("Error reading XML data from file: %s, error: %s\n", fileName, err)
	}

	weaknesses := WeaknessCatalog{}
	error := xml.Unmarshal(xmlData, &weaknesses)

	if error != nil {
		fmt.Printf("Error marshalling: %s\n", error)
		return
	}

	fmt.Println("Weaknesses: %s\n", weaknesses.CatalogName)

	for _, flaw := range weaknesses.Flaws.Findings {
		fmt.Printf("Flaw id: %s, name: %s\n", flaw.ID, flaw.Name)

		for _, mitigation := range flaw.MitigationStrategy.Mitigations {
			fmt.Printf("Mitigations: %s\n", mitigation.Description)
		}
	}

}
