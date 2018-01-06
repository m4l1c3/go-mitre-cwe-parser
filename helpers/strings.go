package helpers

func TrimRandom(s string) string {
	return strings.Replace(s, "   ", "", -1)
}

func Trim(s string) string {
	return TrimRandom(strings.TrimSpace(s))
}
