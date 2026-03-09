package parser

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type BooleanSet bool

func (b *BooleanSet) Capture(values []string) error {
	*b = len(strings.TrimSpace(values[0])) > 0
	return nil
}

type Variable struct {
	Name string `parser:"@Variable"`
}

type String struct {
	Value string `parser:"@String"`
}

type Text struct {
	Value string `parser:"@(String | Ident | Hostname | Filename)"`
}

type Number struct {
	Value int `parser:"@Number"`
}

// AbbreviatedCIDR handles abbreviated CIDR notation used in PF, such as
// 10/8, 10.123/16, or 10.123.0/24. These are expanded to full form
// (e.g. 10.123/16 becomes 10.123.0.0/16) and stored as a netip.Prefix.
type AbbreviatedCIDR struct {
	Prefix netip.Prefix
}

func (a *AbbreviatedCIDR) Capture(values []string) error {
	if len(values) == 0 {
		return errors.New("expecting value for AbbreviatedCIDR")
	}

	raw := values[0]

	// Split into address part and mask part
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid abbreviated CIDR: %s", raw)
	}

	addrPart := parts[0]
	maskStr := parts[1]

	mask, err := strconv.Atoi(maskStr)
	if err != nil || mask < 0 || mask > 32 {
		return fmt.Errorf("invalid CIDR mask in %s", raw)
	}

	// Expand the abbreviated address to 4 octets
	octets := strings.Split(addrPart, ".")
	for len(octets) < 4 {
		octets = append(octets, "0")
	}

	fullAddr := strings.Join(octets, ".")
	fullCIDR := fmt.Sprintf("%s/%d", fullAddr, mask)

	prefix, err := netip.ParsePrefix(fullCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse expanded CIDR %s (from %s): %w", fullCIDR, raw, err)
	}

	a.Prefix = prefix
	return nil
}

type Value[T any] struct {
	Direct      *T        `parser:"@@"`
	Variable    *Variable `parser:"| @@"`
	Parentheses *Value[T] `parser:"| '(' @@ ')'"`
}

type Parentheses[T any] struct {
	Value T `parser:"('(' @@ ')') | @@"`
}

type ValueOrBraceList[T any] struct {
	Values []Value[T] `parser:"('{' EOL* @@ (EOL* ','? EOL* @@)* EOL* '}') | @@"`
}

// ValueBraceOrSpaceList matches either a brace-enclosed list or one or more
// space/comma-separated values without braces. This is used for PF macro
// assignments where values like "192.168.1.1 192.168.2.1" (bare space-separated)
// are valid alongside "{ 192.168.1.1, 192.168.2.1 }" (brace-enclosed).
type ValueBraceOrSpaceList[T any] struct {
	Values []Value[T] `parser:"('{' EOL* @@ (EOL* ','? EOL* @@)* EOL* '}') | @@ (','? @@)*"`
}

type ValueOrRawList[T any] struct {
	Values []Value[T] `parser:"@@ (','? @@)*"`
}

type Comment string

func (c *Comment) Capture(values []string) error {
	if len(values) == 0 {
		return errors.New("expecting value for comment")
	}

	raw := values[0]
	*c = Comment(strings.TrimSpace(raw[1:]))
	return nil
}

// QuotedLiteralList represents a quoted string that may contain network addresses.
// Supported formats:
//   - Brace list with IPs: "{ 2.3.4.5 }" or "{ 1.2.3.4, 5.6.7.8 }"
//   - Brace list with CIDRs: "{ 192.168.1.0/24, 10.0.0.0/8 }"
//   - Space/comma-separated addresses or prefixes: "192.168.211.96/27 192.168.217.192/26"
//   - Single IP: "2.3.4.5"
//   - Single CIDR: "10.0.0.0/8"
//   - Arbitrary raw string (always accepted, stored in Raw)
type QuotedLiteralList struct {
	Addresses []netip.Addr   // Parsed individual IP addresses
	Prefixes  []netip.Prefix // Parsed CIDR prefixes
	Raw       string         // Original string value (without quotes)
}

// Regular expressions for parsing quoted literal lists
var (
	// Matches a brace list pattern: { content }
	braceListPattern = regexp.MustCompile(`^\s*\{\s*(.*?)\s*\}\s*$`)
)

func (q *QuotedLiteralList) Capture(values []string) error {
	if len(values) == 0 {
		return errors.New("expecting value for QuotedLiteralList")
	}

	raw := values[0]

	// Remove surrounding quotes if present
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}

	q.Raw = raw

	// Determine the content to parse: strip braces if present
	content := raw
	if matches := braceListPattern.FindStringSubmatch(raw); matches != nil {
		content = matches[1]
	}

	// Split by commas and/or whitespace to extract individual tokens
	q.parseNetworkTokens(content)

	return nil
}

// parseNetworkTokens splits the content by commas/spaces and tries to parse
// each token as an IP address or CIDR prefix.
func (q *QuotedLiteralList) parseNetworkTokens(content string) {
	// First split by comma, then by whitespace within each part
	var tokens []string
	for _, commaPart := range strings.Split(content, ",") {
		for _, token := range strings.Fields(commaPart) {
			token = strings.TrimSpace(token)
			if token != "" {
				tokens = append(tokens, token)
			}
		}
	}

	for _, token := range tokens {
		// Try CIDR prefix first (e.g. 192.168.1.0/24)
		if prefix, err := netip.ParsePrefix(token); err == nil {
			q.Prefixes = append(q.Prefixes, prefix)
			continue
		}
		// Try plain IP address (e.g. 2.3.4.5)
		if addr, err := netip.ParseAddr(token); err == nil {
			q.Addresses = append(q.Addresses, addr)
			continue
		}
		// Token is not a recognized network address; skip it.
		// The raw string is always available via q.Raw for non-network content.
	}
}
