# GoCatchPhish

<p align="center">
  <img alt="gocatchphish.png" src="https://github.com/ashleymcnamara/gophers/blob/master/GOPHER_SAILOR_STRIPE.png" width="350"/>
  <p align="center">
    <a href="https://github.com/andpalmier/gocatchphish/blob/master/LICENSE"><img alt="Software License" src="https://img.shields.io/badge/license-GPL3-brightgreen.svg?style=flat-square"></a>
    <a href="https://goreportcard.com/report/github.com/andpalmier/gocatchphish"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/andpalmier/gocatchphish?style=flat-square"></a>
    <a href="https://twitter.com/intent/follow?screen_name=andpalmier"><img src="https://img.shields.io/twitter/follow/andpalmier?style=social&logo=twitter" alt="follow on Twitter"></a>
  </p>
</p>

The image above is taken from: [ashleymcnamara/gophers](https://github.com/ashleymcnamara/gophers) and this project is heavily inspired by [x0rz/phishing_catcher](https://github.com/x0rz/phishing_catcher).

The main purpose of `gocatchphish` is to try to detect possible phishing domains by looking for suspicious keywords in the [Certificate Transparency Log](https://www.certificate-transparency.org/) using the [CertStream API](https://certstream.calidog.io/).

The resulting domains will be considered more suspicious based on:

- suspicious keywords in the domain (eg. `paypal.sec-login.com`). [Levenshein distance](https://en.wikipedia.org/wiki/Levenshtein_distance) from some keywords is also taken into account (eg. `paypa1.sec-login.com`)
- suspicious TLDs

If the sum of these elements result in a *suspiciousness level* beyond a certain threshold (default is 50, but can be specified in config file), the domains will be printed in stdout.

## Usage

Build the executable with `go build gocphish.go`. Then:

```
$ gocphish -c config.json

-c: path to config file (json format)
```

## Config.json


An example of config file is provided in `config.json`; you can create your own config and specify the path with `-c`.

The config file allows to specify:

- `suspiciusthreshold`: an integer representing the value of the suspiciousness required to return a domain.
- `toremove`: common strings added in many newly registered domains, such as `cpanel` and `webmail`. The strings in this list are going to be removed when analyzing the domains to avoid duplicate cases.
- `keywords`: containing a list of pairs of strings and integers, where the string is the suspicious keyword and the integer is the corresponding suspiciousness value.
- `suspicioustldsval`: value of suspiciousness to add in case the domain is using one of the suspicious TLDs in `suspicioustlds`.
- `suspicioustlds`: list of the suspicious TLDs, if used, the suspiciousness value of the domain will increase according to the value specified in `suspicioustldsval`.
