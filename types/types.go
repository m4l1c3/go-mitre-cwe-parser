package types

import (
	"encoding/json"
	"encoding/xml"
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

type Vulnerability struct {
	Description     string `json:"description"`
	Title           string `json:"title"`
	Source          string `json:"source"`
	References      string `json:"references"`
	Recommendations string `json:"recommendations"`
	Severity        string `json:"severity"`
}
