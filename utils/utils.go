package utils

import (
	"encoding/json"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
	"os"
	"unicode"
)

// config file struct
type Config struct {
	SuspiciousThreshold int
	ToRemove            []string
	Keywords            map[string]int
	SuspiciousTldsVal   int
	SuspiciousTlds      []string
}

// parse config file
func ParseConfig(configFile string) Config {

	// open configuration file
	file, err := os.Open(configFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// decode the json
	decoder := json.NewDecoder(file)
	conf := Config{}
	err = decoder.Decode(&conf)
	if err != nil {
		panic(err)
	}

	// return the config struct
	return conf
}

// text normalization
func isMn(r rune) bool {
	return unicode.Is(unicode.Mn, r)
}

func NormalizeText(url string) string {
	tran := transform.Chain(norm.NFD, transform.RemoveFunc(isMn), norm.NFC)
	result, _, _ := transform.String(tran, url)
	return result
}
