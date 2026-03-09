package parser

import (
	"github.com/alecthomas/participle/v2/lexer"
)

const (
	IPv4Expr = "(" + `\d{1,3}(\.\d{1,3}){3}` + ")"
	// Require at least two ':' separators to avoid capturing port ranges like "80:443".
	IPv6Expr    = "(" + `[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*` + ")"
	AddressExpr = "(" + IPv4Expr + "|" + IPv6Expr + ")"
	IPRange     = "(" + AddressExpr + "-" + AddressExpr + ")"
	CIDR        = "(" + AddressExpr + `/\d{1,3})`
	// AbbrevCIDR matches abbreviated CIDR notation used in PF, e.g. 10/8, 10.123/16, 10.123.0/24
	AbbrevCIDR = `(\d{1,3}(\.\d{1,3}){0,2}/\d{1,3})`
)

var lex = lexer.MustStateful(lexer.Rules{
	"Root": []lexer.Rule{
		// Matching
		{Name: "EOL", Pattern: `(\n|\r)+`},
		{Name: "IPRange", Pattern: IPRange},
		{Name: "CIDR", Pattern: CIDR},
		{Name: "AbbrevCIDR", Pattern: AbbrevCIDR},
		{Name: "Address", Pattern: AddressExpr},
		{Name: "Variable", Pattern: `\$[a-zA-Z0-9_](\w|-)*`},
		{Name: "MacroIdent", Pattern: `[0-9]+[a-zA-Z_](\w|-|\.)*`},
		{Name: "Ident", Pattern: `[a-zA-Z_](\w|-|\.)*`},
		{Name: "Hexnumber", Pattern: `0x[0-9a-fA-F]+`},
		{Name: "Number", Pattern: `\d+`},
		{Name: "CompOp", Pattern: `!=|<=|>=|<>|><`},
		{Name: "Punct", Pattern: `[-{}()=>!<:,/]`},
		{Name: "Percent", Pattern: `%`},
		{Name: "Comment", Pattern: `#[^\n]*`},
		{Name: "String", Pattern: `"(\\"|[^"])*"`},
		{Name: "Hostname", Pattern: `[a-zA-Z_]+([a-zA-Z_-]*[a-zA-Z_])?(\.[a-zA-Z_]+([a-zA-Z_-]*[a-zA-Z_]))*`},
		{Name: "Filename", Pattern: `/?[a-zA-Z0-9_\./-]+`},
		// Not matching
		{Name: "whitespace", Pattern: `(\\[ \t\v\f]*\r?\n[ \t\v\f]*| |\t)+`},
	},
})
