package main

/*

get suspicious domains from CertStream,
$ goCatchPhishing -c config.json > result.txt

*/

import (
	"flag"
	"fmt"
	"github.com/CaliDog/certstream-go"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"gocatchphish/utils"
	"strings"
)

var (
	// already visited domains
	domainsSet = make(map[string]bool)
	// config file name
	configFile string
	// config data
	conf utils.Config
)

func main() {

	// specify config file with c
	flag.StringVar(&configFile, "c", "config.json", "config file")
	// parse config file
	conf = utils.ParseConfig(configFile)
	// from documentation of certstream-go
	stream, errStream := certstream.CertStreamEventStream(true)

	for {
		select {
		case jq := <-stream:
			// get all domains event
			domains, err := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")
			if err != nil {
				panic(err)
			}

			// parse every domain received
			for _, domain := range domains {
				dom, res := CheckDomain(domain)
				if res {
					fmt.Println(dom)
				}
			}

		case _ = <-errStream:
			continue
		}
	}

}

// callback function when a newly registered domain is found
func CheckDomain(domain string) (string, bool) {
	var dom string

	// normalize text
	dom = utils.NormalizeText(domain)

	// remove prefixes which cause duplicates
	for _, remove := range conf.ToRemove {
		if strings.Contains(domain, remove) {
			dom = strings.TrimPrefix(domain, remove+".")
		}
	}

	// check if already visited
	if !domainsSet[dom] {

		// add to the visited set
		domainsSet[dom] = true

		// suspiciousness of the domain
		urlval := 0

		// loop in suspicious TLDs
		for _, tld := range conf.SuspiciousTlds {

			// check if suspicious tld
			if strings.HasSuffix(dom, tld) {
				urlval += conf.SuspiciousTldsVal
			}
		}

		// Split domain in array
		domarray := strings.Split(dom, ".")

		// loop in the domain array
		for _, partialdomain := range domarray {

			// loop suspicious keywords
			for keyword, value := range conf.Keywords {

				// if suspicious keyword is contained in the
				// element of the domain array, increment the
				// suspiciousness value of the domain with the
				// corresponding value of the keyword
				if strings.Contains(partialdomain, keyword) {
					urlval += value
				}

				// check for similar keywords with levenshtein
				// distance if the value of the keyword is > 60
				if value >= 60 {
					distance := levenshtein.DistanceForStrings([]rune(keyword), []rune(partialdomain), levenshtein.DefaultOptions)
					if distance == 1 {
						urlval += 60
					}
				}
			}
		}

		// return suspicious domains
		if urlval > conf.SuspiciousThreshold {
			return dom, true
		}
	}
	return "", false
}
