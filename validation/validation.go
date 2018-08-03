package validation

import (
	"go-mitre-cwe-parser/types"
)

func VulnerabilityIsValid(catalog string, weakness *types.Weakness) bool {
	return WeaknessIsValid(weakness) && CatalogIsValid(catalog)
}

func WeaknessIsValid(weakness *types.Weakness) bool {
	return (weakness.ID != "" && weakness.Description != "" &&
		weakness.Name != "")
}

func MitigationIsValid(mitigation *types.Mitigation) bool {
	return mitigation != nil && mitigation.Description != ""
}

func CatalogIsValid(catalog string) bool {
	return catalog != ""
}
