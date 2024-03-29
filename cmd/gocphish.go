package main

import (
	"flag"
	"fmt"
	"github.com/CaliDog/certstream-go"
	"github.com/texttheater/golang-levenshtein/levenshtein"
	"strings"
)

var (
	// already visited domains
	domainsSet = make(map[string]bool)
)

func main() {

	// specify config file with c
	configFile := flag.String("c", "config.json", "config file")
	flag.Parse()

	// parse config file
	conf := ParseConfig(*configFile)
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
				dom, res := CheckDomain(domain, conf)
				if res > 0 {
					fmt.Printf("%s [score: %d]\n", dom, res)
					//fmt.Printf("%s\n", dom)
				}
			}

		case _ = <-errStream:
			continue
		}
	}

}

// CheckDomain callback function when a newly registered domain is found
func CheckDomain(domain string, conf Config) (string, int) {
	var dom string

	// normalize text
	dom = NormalizeText(domain)

	// remove prefixes which cause duplicates
	for _, remove := range conf.ToRemove {
		if strings.Contains(dom, remove) {
			dom = strings.TrimPrefix(dom, remove)
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
						urlval += 50
					}
				}
			}
		}

		// return suspicious domains
		if urlval > conf.SuspiciousThreshold {
			return dom, urlval
		}
	}
	return "", 0
}
