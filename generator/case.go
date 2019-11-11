package generator

import (
	"regexp"
	"strings"
)

var matchAllCap = regexp.MustCompile("([a-z0-9])([A-Z])")

// CamelToSnakeCase converts identifier in camel case (FooBarBaz) to snake
// case (foo_bar_baz)
func CamelToSnakeCase(s string) string {
	return strings.ToLower(matchAllCap.ReplaceAllString(s, "${1}_${2}"))
}
