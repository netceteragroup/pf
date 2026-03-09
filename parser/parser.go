package parser

import (
	"bytes"
	"io"
	"regexp"

	"github.com/alecthomas/participle/v2"
)

// continuationRe matches a line-continuation backslash with optional trailing
// horizontal whitespace before newline plus indentation on the next line.
var continuationRe = regexp.MustCompile(`\\[ \t\v\f\p{Zs}]*\r?\n[ \t\v\f\p{Zs}]*`)

var parser = participle.MustBuild[Configuration](
	participle.Lexer(lex),
	participle.Unquote("String"),
)

func init() {
	// fmt.Println(parser.String())
}

func ParseReader(r io.Reader) (conf *Configuration, err error) {
	// Buffer the entire input so we can store the source for raw line extraction.
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return parseBytes(data)
}

func ParseContent[T string | ~[]byte](b T) (conf *Configuration, err error) {
	asAny := any(b)
	switch asAny.(type) {
	case string:
		return parseBytes([]byte(asAny.(string)))
	default:
		return parseBytes(asAny.([]byte))
	}
}

func parseBytes(data []byte) (conf *Configuration, err error) {
	// Join backslash-continued lines into single logical lines before lexing.
	data = continuationRe.ReplaceAll(data, []byte(" "))

	r := bytes.NewReader(data)
	conf, err = parser.Parse(":reader:", r)
	if err != nil {
		return nil, err
	}
	conf.source = string(data)
	conf.populateRawText()
	return conf, nil
}
