package parser_test

import (
	"net/netip"
	"testing"

	"github.com/RogueTeam/pf/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_RawStringVariables_And_Tables(t *testing.T) {
	t.Run("raw string with space-separated CIDR prefixes", func(t *testing.T) {
		input := `some_net = "192.168.0.96/27 192.168.1.192/26 10.123.0.96/27 10.123.1.192/26"
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle raw string with space-separated CIDRs")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment, "line should be an assignment")
		assert.Equal(t, "some_net", assignment.Variable)

		require.NotEmpty(t, assignment.Value.Values)
		firstValue := assignment.Value.Values[0]
		require.NotNil(t, firstValue.Direct)

		literal := firstValue.Direct
		require.NotNil(t, literal.QuotedBraceList, "should be parsed as QuotedBraceList")

		// Should have 4 CIDR prefixes
		require.Len(t, literal.QuotedBraceList.Prefixes, 4, "expected 4 CIDR prefixes")
		expectedPrefixes := []netip.Prefix{
			netip.MustParsePrefix("192.168.0.96/27"),
			netip.MustParsePrefix("192.168.1.192/26"),
			netip.MustParsePrefix("10.123.0.96/27"),
			netip.MustParsePrefix("10.123.1.192/26"),
		}
		assert.Equal(t, expectedPrefixes, literal.QuotedBraceList.Prefixes)

		// Raw string should also be available
		assert.Equal(t, "192.168.0.96/27 192.168.1.192/26 10.123.0.96/27 10.123.1.192/26",
			literal.QuotedBraceList.Raw)
	})

	t.Run("full example: variable + table + pass rule", func(t *testing.T) {
		input := `some_net            = "192.168.0.96/27 192.168.1.192/26 10.123.0.96/27 10.123.1.192/26"
table <some_hosts> { $some_net }
pass log quick proto tcp  from $some_host      to <some_hosts>        port { 443 6556 }
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle variable + table + pass rule")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 3, "expected 3 lines")

		// Line 1: Assignment
		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment)
		assert.Equal(t, "some_net", assignment.Variable)
		require.NotEmpty(t, assignment.Value.Values)
		require.NotNil(t, assignment.Value.Values[0].Direct)
		require.NotNil(t, assignment.Value.Values[0].Direct.QuotedBraceList)
		assert.Len(t, assignment.Value.Values[0].Direct.QuotedBraceList.Prefixes, 4)

		// Line 2: Table rule
		tableRule := conf.Line[1].TableRule
		require.NotNil(t, tableRule, "second line should be a table rule")
		require.NotNil(t, tableRule.Name.Direct)
		assert.Equal(t, "some_hosts", tableRule.Name.Direct.Value)
		require.NotEmpty(t, tableRule.Options)

		// Line 3: Pass rule
		pfRule := conf.Line[2].PfRule
		require.NotNil(t, pfRule, "third line should be a PF rule")
		assert.True(t, bool(pfRule.Action.Pass))
	})

	t.Run("raw string with braced CIDR prefixes", func(t *testing.T) {
		input := `nets = "{ 10.0.0.0/8, 172.16.0.0/12 }"
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle braced CIDR prefixes in quoted string")
		require.NotNil(t, conf)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment)
		require.NotEmpty(t, assignment.Value.Values)

		literal := assignment.Value.Values[0].Direct
		require.NotNil(t, literal)
		require.NotNil(t, literal.QuotedBraceList)
		assert.Len(t, literal.QuotedBraceList.Prefixes, 2, "expected 2 CIDR prefixes")
		assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), literal.QuotedBraceList.Prefixes[0])
		assert.Equal(t, netip.MustParsePrefix("172.16.0.0/12"), literal.QuotedBraceList.Prefixes[1])
	})

	t.Run("raw string with mixed IPs and CIDRs", func(t *testing.T) {
		input := `mixed = "1.2.3.4 10.0.0.0/8 5.6.7.8"
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle mixed IPs and CIDRs")
		require.NotNil(t, conf)

		literal := conf.Line[0].Assignment.Value.Values[0].Direct
		require.NotNil(t, literal.QuotedBraceList)
		assert.Len(t, literal.QuotedBraceList.Addresses, 2, "expected 2 IP addresses")
		assert.Len(t, literal.QuotedBraceList.Prefixes, 1, "expected 1 CIDR prefix")
		assert.Equal(t, netip.MustParseAddr("1.2.3.4"), literal.QuotedBraceList.Addresses[0])
		assert.Equal(t, netip.MustParseAddr("5.6.7.8"), literal.QuotedBraceList.Addresses[1])
		assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), literal.QuotedBraceList.Prefixes[0])
	})

	t.Run("arbitrary raw string variable", func(t *testing.T) {
		// Even strings that don't contain network addresses should parse
		input := `label_text = "some arbitrary label text"
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle arbitrary raw strings in variables")
		require.NotNil(t, conf)

		literal := conf.Line[0].Assignment.Value.Values[0].Direct
		require.NotNil(t, literal.QuotedBraceList)
		assert.Equal(t, "some arbitrary label text", literal.QuotedBraceList.Raw)
		assert.Empty(t, literal.QuotedBraceList.Addresses, "no IPs expected")
		assert.Empty(t, literal.QuotedBraceList.Prefixes, "no prefixes expected")
	})

	t.Run("braced IP list still works", func(t *testing.T) {
		// Ensure the original braced IP format still works
		input := `ips = "{ 2.3.4.5 }"
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err)

		literal := conf.Line[0].Assignment.Value.Values[0].Direct
		require.NotNil(t, literal.QuotedBraceList)
		require.Len(t, literal.QuotedBraceList.Addresses, 1)
		assert.Equal(t, netip.MustParseAddr("2.3.4.5"), literal.QuotedBraceList.Addresses[0])
	})

	t.Run("table with variable reference from raw string", func(t *testing.T) {
		input := `some_net = "192.168.0.96/27 192.168.1.192/26"
table <a_hosts> { $some_net }
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle table referencing raw string variable")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 2)

		// Verify the table rule
		tableRule := conf.Line[1].TableRule
		require.NotNil(t, tableRule)
		assert.Equal(t, "a_hosts", tableRule.Name.Direct.Value)

		// The table option should have an Addresses entry with a variable reference
		require.NotEmpty(t, tableRule.Options)
		addrOption := tableRule.Options[0]
		require.NotNil(t, addrOption.Addresses)
		require.NotEmpty(t, addrOption.Addresses.Values)
	})
}

func Test_SpaceSeparatedBareAssignment(t *testing.T) {
	t.Run("bare space-separated IPs in assignment", func(t *testing.T) {
		input := "o_lb = 192.168.1.48 192.168.2.48\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle space-separated bare IPs")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment)
		assert.Equal(t, "o_lb", assignment.Variable)

		// Should have 2 values parsed individually
		require.Len(t, assignment.Value.Values, 2, "expected 2 IP values")

		// First IP
		first := assignment.Value.Values[0]
		require.NotNil(t, first.Direct)
		require.NotNil(t, first.Direct.Address.IP)
		require.NotNil(t, first.Direct.Address.IP.Direct)
		require.NotNil(t, first.Direct.Address.IP.Direct.Address)
		assert.Equal(t, netip.MustParseAddr("192.168.1.48"), *first.Direct.Address.IP.Direct.Address)

		// Second IP
		second := assignment.Value.Values[1]
		require.NotNil(t, second.Direct)
		require.NotNil(t, second.Direct.Address.IP)
		require.NotNil(t, second.Direct.Address.IP.Direct)
		require.NotNil(t, second.Direct.Address.IP.Direct.Address)
		assert.Equal(t, netip.MustParseAddr("192.168.2.48"), *second.Direct.Address.IP.Direct.Address)
	})

	t.Run("full PF config: bare IPs + table + pass rule", func(t *testing.T) {
		input := `o_lb = 192.168.1.48 192.168.2.48
n_host = 192.168.3.112

table <o_lb> { $o_lb }

pass log quick proto tcp from $n_host            to <o_lb>    port 22555
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle the full real PF config excerpt")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 4, "expected 4 lines (2 assignments + table + rule)")

		// Line 1: o_lb assignment with 2 IPs
		assign1 := conf.Line[0].Assignment
		require.NotNil(t, assign1)
		assert.Equal(t, "o_lb", assign1.Variable)
		require.Len(t, assign1.Value.Values, 2, "o_lb should have 2 values")

		// Line 2: n_host assignment with 1 IP
		assign2 := conf.Line[1].Assignment
		require.NotNil(t, assign2)
		assert.Equal(t, "n_host", assign2.Variable)
		require.Len(t, assign2.Value.Values, 1, "n_host should have 1 value")

		// Line 3: table rule
		tableRule := conf.Line[2].TableRule
		require.NotNil(t, tableRule, "third line should be a table rule")
		require.NotNil(t, tableRule.Name.Direct)
		assert.Equal(t, "o_lb", tableRule.Name.Direct.Value)

		// Line 4: pass rule
		pfRule := conf.Line[3].PfRule
		require.NotNil(t, pfRule, "fourth line should be a PF rule")
		assert.True(t, bool(pfRule.Action.Pass))
	})

	t.Run("single bare IP still works", func(t *testing.T) {
		input := "n_host = 192.168.3.112\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment)
		require.Len(t, assignment.Value.Values, 1)
		require.NotNil(t, assignment.Value.Values[0].Direct)
		require.NotNil(t, assignment.Value.Values[0].Direct.Address.IP)
		require.NotNil(t, assignment.Value.Values[0].Direct.Address.IP.Direct)
		require.NotNil(t, assignment.Value.Values[0].Direct.Address.IP.Direct.Address)
		assert.Equal(t, netip.MustParseAddr("192.168.3.112"),
			*assignment.Value.Values[0].Direct.Address.IP.Direct.Address)
	})

	t.Run("brace-enclosed list still works with new type", func(t *testing.T) {
		input := "multi_ip = { 1.2.3.4, 5.6.7.8 }\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment)
		require.Len(t, assignment.Value.Values, 2, "brace list should have 2 values")
	})
}

func Test_TableWithSelfAndAddresses(t *testing.T) {
	t.Run("table with persist + self + multiple addresses", func(t *testing.T) {
		input := "table <myself> persist      { self 224.0.0.5 224.0.0.6 224.0.0.18 }\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle table with self and addresses in brace list")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		tableRule := conf.Line[0].TableRule
		require.NotNil(t, tableRule, "line should be a table rule")
		require.NotNil(t, tableRule.Name.Direct)
		assert.Equal(t, "myself", tableRule.Name.Direct.Value)

		// Should have 2 options: persist + addresses
		require.Len(t, tableRule.Options, 2, "expected 2 table options (persist + addresses)")

		// First option: persist
		assert.True(t, bool(tableRule.Options[0].Persist), "first option should be persist")

		// Second option: addresses brace list with 4 entries (self + 3 IPs)
		addrOption := tableRule.Options[1]
		require.NotNil(t, addrOption.Addresses, "second option should be addresses")
		require.Len(t, addrOption.Addresses.Values, 4, "expected 4 entries: self + 3 addresses")

		// First entry should be self
		firstEntry := addrOption.Addresses.Values[0]
		require.NotNil(t, firstEntry.Direct)
		assert.True(t, bool(firstEntry.Direct.Target.Self), "first entry should be self")

		// Remaining entries should be IP addresses
		expectedIPs := []netip.Addr{
			netip.MustParseAddr("224.0.0.5"),
			netip.MustParseAddr("224.0.0.6"),
			netip.MustParseAddr("224.0.0.18"),
		}
		for i, expectedIP := range expectedIPs {
			entry := addrOption.Addresses.Values[i+1]
			require.NotNil(t, entry.Direct, "entry %d should be direct", i+1)
			require.NotNil(t, entry.Direct.Target.Address, "entry %d should have an address", i+1)
			assert.Equal(t, expectedIP, *entry.Direct.Target.Address, "entry %d IP mismatch", i+1)
		}
	})

	t.Run("table with addresses only in brace list", func(t *testing.T) {
		input := "table <myself> { 224.0.0.5 224.0.0.6 }\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)

		tableRule := conf.Line[0].TableRule
		require.NotNil(t, tableRule)
		require.Len(t, tableRule.Options, 1)
		require.NotNil(t, tableRule.Options[0].Addresses)
		require.Len(t, tableRule.Options[0].Addresses.Values, 2)
	})

	t.Run("table with persist + self only", func(t *testing.T) {
		input := "table <myself> persist { self }\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)

		tableRule := conf.Line[0].TableRule
		require.NotNil(t, tableRule)
		require.Len(t, tableRule.Options, 2)
		assert.True(t, bool(tableRule.Options[0].Persist))
		require.NotNil(t, tableRule.Options[1].Addresses)
		require.Len(t, tableRule.Options[1].Addresses.Values, 1)
		assert.True(t, bool(tableRule.Options[1].Addresses.Values[0].Direct.Target.Self))
	})

	t.Run("empty table definition with explicit braces", func(t *testing.T) {
		input := "table <bad_src_track>          { }\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		tableRule := conf.Line[0].TableRule
		require.NotNil(t, tableRule)
		require.NotNil(t, tableRule.Name.Direct)
		assert.Equal(t, "bad_src_track", tableRule.Name.Direct.Value)
		assert.True(t, bool(tableRule.EmptyBlock))
		assert.Empty(t, tableRule.Options)
	})
}

func Test_IncludeDirective(t *testing.T) {
	t.Run("include with quoted path", func(t *testing.T) {
		input := "include \"/etc/pf_self.conf\"\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle include directive")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		inc := conf.Line[0].Include
		require.NotNil(t, inc, "line should be an Include")
		require.NotNil(t, inc.Filename.Direct, "filename should be direct")
		assert.Equal(t, "/etc/pf_self.conf", inc.Filename.Direct.Value)
	})

	t.Run("include among other lines", func(t *testing.T) {
		input := "set block-policy drop\ninclude \"/etc/pf_self.conf\"\npass log quick proto tcp from any to any port 22\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle include among other lines")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 3, "expected 3 lines")

		// Line 1: set option
		require.NotNil(t, conf.Line[0].Option)

		// Line 2: include
		require.NotNil(t, conf.Line[1].Include)
		assert.Equal(t, "/etc/pf_self.conf", conf.Line[1].Include.Filename.Direct.Value)

		// Line 3: pass rule
		require.NotNil(t, conf.Line[2].PfRule)
	})

	t.Run("include does not break variable assignment", func(t *testing.T) {
		// Ensure that a variable named starting with "include" still works as assignment
		input := "include_path = \"/etc/pf.conf\"\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		// This should be parsed as an assignment, not an include
		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment, "line should be an assignment")
		assert.Equal(t, "include_path", assignment.Variable)
	})
}

func Test_AbbreviatedCIDR(t *testing.T) {
	t.Run("block rule with abbreviated CIDR notation", func(t *testing.T) {
		input := "block quick proto udp from 10.123/16 to 192.168/16 port 514\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle abbreviated CIDR notation")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule, "line should be a PfRule")
		require.NotNil(t, rule.Action.Block, "action should be block")
		require.NotNil(t, rule.Hosts)
		require.NotEmpty(t, rule.Hosts.HostsFromTo)
	})

	t.Run("abbreviated CIDR expands correctly - two octets", func(t *testing.T) {
		input := "pass from 10.123/16 to any\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule)

		// Navigate to the from host target
		fromTo := rule.Hosts.HostsFromTo[0]
		require.NotNil(t, fromTo.From)
		require.NotNil(t, fromTo.From.Target)
		require.NotEmpty(t, fromTo.From.Target.Values)

		target := fromTo.From.Target.Values[0].Direct
		require.NotNil(t, target)
		require.NotNil(t, target.Host)
		require.NotNil(t, target.Host.Address)
		require.NotNil(t, target.Host.Address.IP)
		require.NotNil(t, target.Host.Address.IP.Direct)
		require.NotNil(t, target.Host.Address.IP.Direct.AbbrevCIDR, "should be parsed as AbbrevCIDR")

		prefix := target.Host.Address.IP.Direct.AbbrevCIDR.Prefix
		assert.Equal(t, netip.MustParsePrefix("10.123.0.0/16"), prefix,
			"10.123/16 should expand to 10.123.0.0/16")
	})

	t.Run("abbreviated CIDR with one octet", func(t *testing.T) {
		input := "pass from 10/8 to any\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle single-octet abbreviated CIDR")
		require.NotNil(t, conf)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule)

		fromTo := rule.Hosts.HostsFromTo[0]
		target := fromTo.From.Target.Values[0].Direct
		require.NotNil(t, target.Host.Address.IP.Direct.AbbrevCIDR)

		prefix := target.Host.Address.IP.Direct.AbbrevCIDR.Prefix
		assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), prefix,
			"10/8 should expand to 10.0.0.0/8")
	})

	t.Run("abbreviated CIDR with three octets", func(t *testing.T) {
		input := "pass from 192.168.1/24 to any\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle three-octet abbreviated CIDR")
		require.NotNil(t, conf)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule)

		fromTo := rule.Hosts.HostsFromTo[0]
		target := fromTo.From.Target.Values[0].Direct
		require.NotNil(t, target.Host.Address.IP.Direct.AbbrevCIDR)

		prefix := target.Host.Address.IP.Direct.AbbrevCIDR.Prefix
		assert.Equal(t, netip.MustParsePrefix("192.168.1.0/24"), prefix,
			"192.168.1/24 should expand to 192.168.1.0/24")
	})

	t.Run("full CIDR still works", func(t *testing.T) {
		input := "pass from 192.168.1.0/24 to any\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "full CIDR should still work")
		require.NotNil(t, conf)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule)

		fromTo := rule.Hosts.HostsFromTo[0]
		target := fromTo.From.Target.Values[0].Direct
		require.NotNil(t, target.Host.Address.IP.Direct.CIDR, "full CIDR should be parsed as CIDR, not AbbrevCIDR")
		assert.Equal(t, netip.MustParsePrefix("192.168.1.0/24"), *target.Host.Address.IP.Direct.CIDR)
	})
}

func Test_InterfaceModifier(t *testing.T) {
	t.Run("nat-to with interface modifier :0", func(t *testing.T) {
		input := "pass out log quick on vlan5 proto tcp from <some_a_hosts> to <some_fw> port 22 nat-to (vlan5:0)\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle nat-to with interface modifier :0")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule)
		assert.True(t, bool(rule.Action.Pass))

		// Find the NatTo in filter options
		require.NotNil(t, rule.FilterOptions)
		var natTo *parser.NatTo
		for _, opt := range rule.FilterOptions.Values {
			if opt.Direct != nil && opt.Direct.NatTo != nil {
				natTo = opt.Direct.NatTo
				break
			}
		}
		require.NotNil(t, natTo, "should have NatTo filter option")
		require.NotEmpty(t, natTo.Host.Values)

		host := natTo.Host.Values[0].Direct
		require.NotNil(t, host, "nat-to host should be direct")
		require.NotNil(t, host.ParenInterface, "should be parsed as parenthesized interface")
		require.NotNil(t, host.ParenInterface.Direct)
		assert.Equal(t, "vlan5", host.ParenInterface.Direct.Value)
		require.NotNil(t, host.InterfaceModifier)
		assert.Equal(t, "0", *host.InterfaceModifier)
	})

	t.Run("nat-to with parenthesized interface without modifier", func(t *testing.T) {
		input := "pass from any to any nat-to (em0)\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle nat-to with parenthesized interface (no modifier)")
		require.NotNil(t, conf)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule)

		var natTo *parser.NatTo
		for _, opt := range rule.FilterOptions.Values {
			if opt.Direct != nil && opt.Direct.NatTo != nil {
				natTo = opt.Direct.NatTo
				break
			}
		}
		require.NotNil(t, natTo)

		host := natTo.Host.Values[0].Direct
		require.NotNil(t, host)
		require.NotNil(t, host.ParenInterface)
		require.NotNil(t, host.ParenInterface.Direct)
		assert.Equal(t, "em0", host.ParenInterface.Direct.Value)
		assert.Nil(t, host.InterfaceModifier, "no modifier expected")
	})

	t.Run("nat-to with :broadcast modifier", func(t *testing.T) {
		input := "pass from any to any nat-to (em0:broadcast)\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle :broadcast modifier")
		require.NotNil(t, conf)

		var natTo *parser.NatTo
		for _, opt := range conf.Line[0].PfRule.FilterOptions.Values {
			if opt.Direct != nil && opt.Direct.NatTo != nil {
				natTo = opt.Direct.NatTo
				break
			}
		}
		require.NotNil(t, natTo)

		host := natTo.Host.Values[0].Direct
		require.NotNil(t, host.InterfaceModifier)
		assert.Equal(t, "broadcast", *host.InterfaceModifier)
	})

	t.Run("nat-to with :network modifier", func(t *testing.T) {
		input := "pass from any to any nat-to (em0:network)\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle :network modifier")
		require.NotNil(t, conf)

		var natTo *parser.NatTo
		for _, opt := range conf.Line[0].PfRule.FilterOptions.Values {
			if opt.Direct != nil && opt.Direct.NatTo != nil {
				natTo = opt.Direct.NatTo
				break
			}
		}
		require.NotNil(t, natTo)

		host := natTo.Host.Values[0].Direct
		require.NotNil(t, host.InterfaceModifier)
		assert.Equal(t, "network", *host.InterfaceModifier)
	})

	t.Run("nat-to with :peer modifier", func(t *testing.T) {
		input := "pass from any to any nat-to (em0:peer)\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle :peer modifier")
		require.NotNil(t, conf)

		var natTo *parser.NatTo
		for _, opt := range conf.Line[0].PfRule.FilterOptions.Values {
			if opt.Direct != nil && opt.Direct.NatTo != nil {
				natTo = opt.Direct.NatTo
				break
			}
		}
		require.NotNil(t, natTo)

		host := natTo.Host.Values[0].Direct
		require.NotNil(t, host.InterfaceModifier)
		assert.Equal(t, "peer", *host.InterfaceModifier)
	})

	t.Run("rdr-to with interface modifier", func(t *testing.T) {
		input := "pass in log quick proto tcp from any to any rdr-to (lo0:0)\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle rdr-to with interface modifier")
		require.NotNil(t, conf)

		var rdrTo *parser.RdrTo
		for _, opt := range conf.Line[0].PfRule.FilterOptions.Values {
			if opt.Direct != nil && opt.Direct.RdrTo != nil {
				rdrTo = opt.Direct.RdrTo
				break
			}
		}
		require.NotNil(t, rdrTo)

		host := rdrTo.Host.Values[0].Direct
		require.NotNil(t, host.ParenInterface)
		assert.Equal(t, "lo0", host.ParenInterface.Direct.Value)
		require.NotNil(t, host.InterfaceModifier)
		assert.Equal(t, "0", *host.InterfaceModifier)
	})

	t.Run("nat-to with bare interface still works", func(t *testing.T) {
		// Without parentheses - should use Address path
		input := "pass from any to any nat-to 1.2.3.4\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "nat-to with bare IP should still work")
		require.NotNil(t, conf)

		var natTo *parser.NatTo
		for _, opt := range conf.Line[0].PfRule.FilterOptions.Values {
			if opt.Direct != nil && opt.Direct.NatTo != nil {
				natTo = opt.Direct.NatTo
				break
			}
		}
		require.NotNil(t, natTo)

		host := natTo.Host.Values[0].Direct
		require.NotNil(t, host)
		require.NotNil(t, host.Address, "bare IP should use Address path")
		assert.Nil(t, host.ParenInterface, "bare IP should not use ParenInterface")
	})
}

func Test_VariableReferencingOtherVariables(t *testing.T) {
	t.Run("variable referencing other variables parses correctly", func(t *testing.T) {
		input := `b_b_v = 192.168.0.157
b_o_v = 192.168.0.13
b_y_v = 192.168.1.8

b_v_hosts = $b_b_v $b_o_v $b_y_v
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle variables referencing other variables")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 4, "expected 4 lines (3 IP assignments + 1 var-ref assignment)")

		// Lines 0-2: direct IP assignments
		for i, expectedVar := range []string{"b_b_v", "b_o_v", "b_y_v"} {
			assign := conf.Line[i].Assignment
			require.NotNil(t, assign, "line %d should be an assignment", i)
			assert.Equal(t, expectedVar, assign.Variable)
			require.Len(t, assign.Value.Values, 1)
			require.NotNil(t, assign.Value.Values[0].Direct)
			require.NotNil(t, assign.Value.Values[0].Direct.Address.IP)
			require.NotNil(t, assign.Value.Values[0].Direct.Address.IP.Direct)
			require.NotNil(t, assign.Value.Values[0].Direct.Address.IP.Direct.Address)
		}

		expectedIPs := []netip.Addr{
			netip.MustParseAddr("192.168.0.157"),
			netip.MustParseAddr("192.168.0.13"),
			netip.MustParseAddr("192.168.1.8"),
		}
		for i, expectedIP := range expectedIPs {
			addr := conf.Line[i].Assignment.Value.Values[0].Direct.Address.IP.Direct.Address
			assert.Equal(t, expectedIP, *addr)
		}

		// Line 3: b_v_hosts = $b_b_v $b_o_v $b_y_v
		assign := conf.Line[3].Assignment
		require.NotNil(t, assign)
		assert.Equal(t, "b_v_hosts", assign.Variable)
		require.Len(t, assign.Value.Values, 3, "expected 3 variable references")

		// Each value should be a variable reference, accessible via Address.IP.Variable
		expectedVarRefs := []string{"$b_b_v", "$b_o_v", "$b_y_v"}
		for i, expectedRef := range expectedVarRefs {
			val := assign.Value.Values[i]

			// The value is parsed as Direct -> Literal -> Address -> IP -> Variable
			// (not as Value[Literal].Variable, since the $var token is consumed
			// deeper in the parse tree by Value[IP].Variable)
			require.NotNil(t, val.Direct, "value %d should have Direct", i)
			require.NotNil(t, val.Direct.Address.IP, "value %d should have Address.IP", i)
			require.NotNil(t, val.Direct.Address.IP.Variable,
				"value %d should be a variable reference via Address.IP.Variable", i)
			assert.Equal(t, expectedRef, val.Direct.Address.IP.Variable.Name,
				"value %d variable name mismatch", i)
		}
	})

	t.Run("variable resolution through collected variables", func(t *testing.T) {
		// This test simulates the variable collection and resolution logic
		// that the consumer (pf-analysis) would perform. It validates that
		// when variables reference other variables, the referenced values
		// can be resolved by looking them up in the already-collected map.
		input := `b_b_v = 192.168.0.157
b_o_v = 192.168.0.13
b_y_v = 192.168.1.8

b_v_hosts = $b_b_v $b_o_v $b_y_v
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err)

		// Simulate collectPfVariables: iterate lines in order,
		// building a variable map. When a variable value is a reference,
		// resolve it from the map.
		variables := make(map[string][]string)

		for _, line := range conf.Line {
			assign := line.Assignment
			if assign == nil {
				continue
			}

			varName := "$" + assign.Variable
			varValues := make([]string, 0)

			for _, val := range assign.Value.Values {
				if val.Direct == nil {
					continue
				}

				parsed := val.Direct

				// Case 1: direct IP address
				if parsed.Address.IP != nil && parsed.Address.IP.Direct != nil {
					ip := parsed.Address.IP.Direct
					if ip.Address != nil {
						varValues = append(varValues, ip.Address.String())
					}
					continue
				}

				// Case 2: variable reference (e.g. $b_b_v)
				if parsed.Address.IP != nil && parsed.Address.IP.Variable != nil {
					refName := parsed.Address.IP.Variable.Name
					refValues, found := variables[refName]
					require.True(t, found,
						"referenced variable %s should already be defined", refName)
					varValues = append(varValues, refValues...)
					continue
				}
			}

			variables[varName] = varValues
		}

		// Verify the resolved variables
		assert.Equal(t, []string{"192.168.0.157"}, variables["$b_b_v"])
		assert.Equal(t, []string{"192.168.0.13"}, variables["$b_o_v"])
		assert.Equal(t, []string{"192.168.1.8"}, variables["$b_y_v"])

		// The key assertion: b_v_hosts should have all 3 IPs resolved
		assert.Equal(t, []string{"192.168.0.157", "192.168.0.13", "192.168.1.8"},
			variables["$b_v_hosts"],
			"b_v_hosts should resolve variable references to their IP values")
	})
}

// Test_TableReferenceInRule documents how PF table references (angle-bracket
// syntax like <a_hosts>) are represented in the parse tree.
//
// In PF, <table_name> in a host context refers to a previously defined table.
// The parser captures these via the Host.AsString field (grammar: '<' @@ '>').
// This is the intended design: Host has three alternatives:
//   - ParenInterface: for (interface:modifier) syntax
//   - Address: for IPs, CIDRs, hostnames, variables
//   - AsString: for <table_name> references
//
// The consumer code (pf-analysis) resolves Host.AsString.Direct.Value by
// looking up the table name in the collected variables/tables map.
func Test_TableReferenceInRule(t *testing.T) {
	t.Run("table references are parsed via Host.AsString", func(t *testing.T) {
		input := "pass log quick proto tcp from <a_hosts>     to <f_o>  port 22\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule)
		assert.True(t, bool(rule.Action.Pass))

		require.NotNil(t, rule.Hosts)
		require.Len(t, rule.Hosts.HostsFromTo, 2, "expected from + to")

		// FROM: <a_hosts>
		from := rule.Hosts.HostsFromTo[0].From
		require.NotNil(t, from)
		require.NotNil(t, from.Target)
		require.Len(t, from.Target.Values, 1)

		fromHost := from.Target.Values[0].Direct.Host
		require.NotNil(t, fromHost, "from should have a Host")

		// The table reference is captured in Host.AsString, not Host.Address.
		// This is the intended parser behavior for <table_name> syntax.
		assert.Nil(t, fromHost.Address, "table ref should NOT be in Address")
		assert.Nil(t, fromHost.ParenInterface, "table ref should NOT be in ParenInterface")
		require.NotNil(t, fromHost.AsString, "table ref should be in AsString")
		require.NotNil(t, fromHost.AsString.Direct)
		assert.Equal(t, "a_hosts", fromHost.AsString.Direct.Value,
			"AsString.Direct.Value should contain the table name without angle brackets")

		// TO: <f_o> port 22
		to := rule.Hosts.HostsFromTo[1].To
		require.NotNil(t, to)
		require.NotNil(t, to.Target)
		require.Len(t, to.Target.Values, 1)

		toHost := to.Target.Values[0].Direct.Host
		require.NotNil(t, toHost)
		assert.Nil(t, toHost.Address)
		require.NotNil(t, toHost.AsString)
		require.NotNil(t, toHost.AsString.Direct)
		assert.Equal(t, "f_o", toHost.AsString.Direct.Value)

		// Port should be 22
		require.NotNil(t, to.Port)
		require.Len(t, to.Port.Ports.Values, 1)
		portOp := to.Port.Ports.Values[0].Direct
		require.NotNil(t, portOp)
		require.NotNil(t, portOp.Unary)
		require.NotNil(t, portOp.Unary.Number)
		require.NotNil(t, portOp.Unary.Number.Direct)
		assert.Equal(t, 22, portOp.Unary.Number.Direct.Value)
	})

	t.Run("full config with table definition and rule using table reference", func(t *testing.T) {
		input := `some_net = "192.168.0.96/27"
table <a_hosts> { $some_net }
table <f_o> { 10.0.0.0/8 }
pass log quick proto tcp from <a_hosts> to <f_o> port 22
`
		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 4)

		// Line 0: Assignment
		require.NotNil(t, conf.Line[0].Assignment)

		// Line 1: Table <a_hosts>
		require.NotNil(t, conf.Line[1].TableRule)
		assert.Equal(t, "a_hosts", conf.Line[1].TableRule.Name.Direct.Value)

		// Line 2: Table <f_o>
		require.NotNil(t, conf.Line[2].TableRule)
		assert.Equal(t, "f_o", conf.Line[2].TableRule.Name.Direct.Value)

		// Line 3: Pass rule referencing both tables
		rule := conf.Line[3].PfRule
		require.NotNil(t, rule)

		fromHost := rule.Hosts.HostsFromTo[0].From.Target.Values[0].Direct.Host
		require.NotNil(t, fromHost.AsString)
		assert.Equal(t, "a_hosts", fromHost.AsString.Direct.Value,
			"from table ref should match table name defined on line 1")

		toHost := rule.Hosts.HostsFromTo[1].To.Target.Values[0].Direct.Host
		require.NotNil(t, toHost.AsString)
		assert.Equal(t, "f_o", toHost.AsString.Direct.Value,
			"to table ref should match table name defined on line 2")
	})

	t.Run("negated table reference", func(t *testing.T) {
		input := "pass from ! <bad_hosts> to any\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)

		fromHost := conf.Line[0].PfRule.Hosts.HostsFromTo[0].From.Target.Values[0].Direct.Host
		require.NotNil(t, fromHost)
		assert.True(t, bool(fromHost.Negate), "table ref should be negated")
		require.NotNil(t, fromHost.AsString)
		assert.Equal(t, "bad_hosts", fromHost.AsString.Direct.Value)
	})
}

func Test_StateOverload_TableRefBeforeClosingParen(t *testing.T) {
	input := "pass log quick proto tcp from any to $w port 443 keep state (max-src-conn 2000, max-src-conn-rate 200/1 overload <bw>)\n"

	conf, err := parser.ParseContent(input)
	require.NoError(t, err)
	require.NotNil(t, conf)
	require.Len(t, conf.Line, 1)
	require.NotNil(t, conf.Line[0].PfRule)
}
