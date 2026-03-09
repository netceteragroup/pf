package parser_test

import (
	"net/netip"
	"testing"

	"github.com/RogueTeam/pf/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_VariableAssignment_IPAddressAccess(t *testing.T) {
	t.Run("variable with braced IP address should be accessible as IP", func(t *testing.T) {
		// This test validates that when a variable is assigned a value like "{ 2.3.4.5 }",
		// the parser should allow access to the IP address (2.3.4.5) as an actual IP,
		// not just as a raw string containing braces.
		input := `o_c = "{ 2.3.4.5 }"
pass log quick proto udp  from (self)  to $o_c port 514   keep state (no-sync)`

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "failed to parse configuration")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 2, "expected 2 lines (assignment + rule)")

		// First line should be the assignment
		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment, "first line should be an assignment")
		assert.Equal(t, "o_c", assignment.Variable, "variable name should be 'o_c'")

		// The Value should be a ValueOrBraceList[Literal]
		// We expect to be able to access the IP address 2.3.4.5 from the assignment
		require.NotEmpty(t, assignment.Value.Values, "assignment should have values")

		// Current implementation flaw: the value is captured as a whole string "{ 2.3.4.5 }"
		// instead of being parsed as a brace list containing an IP address.
		//
		// Expected behavior: the parser should recognize the braces and parse the content
		// as a Literal with an Address containing IP 2.3.4.5
		//
		// This test documents the expected behavior - it will fail until the parser is fixed.

		// Get the first value from the assignment
		firstValue := assignment.Value.Values[0]

		// The value should be parsed as a Direct Literal (not via Variable or Parentheses)
		require.NotNil(t, firstValue.Direct, "value should be parsed directly, not as a variable reference")

		literal := firstValue.Direct

		// First check if QuotedBraceList was populated (the fix)
		if literal.QuotedBraceList != nil {
			// SUCCESS: The quoted brace list was parsed and IP addresses extracted
			require.NotEmpty(t, literal.QuotedBraceList.Addresses, "QuotedBraceList should contain IP addresses")

			expectedIP := netip.MustParseAddr("2.3.4.5")
			assert.Equal(t, expectedIP, literal.QuotedBraceList.Addresses[0], "IP address should be 2.3.4.5")
			t.Logf("SUCCESS: IP address is properly accessible via QuotedBraceList.Addresses: %v", literal.QuotedBraceList.Addresses)
			return
		}

		// The Literal should have an Address with an IP, not just a String
		// This is the key assertion that validates the fix
		if literal.Address.IP != nil && literal.Address.IP.Direct != nil {
			// SUCCESS: The IP address is properly accessible
			ip := literal.Address.IP.Direct

			// Validate we can access the actual IP address
			if ip.Address != nil {
				expectedIP := netip.MustParseAddr("2.3.4.5")
				assert.Equal(t, expectedIP, *ip.Address, "IP address should be 2.3.4.5")
				t.Log("SUCCESS: IP address is properly accessible as netip.Addr")
			} else if ip.CIDR != nil {
				t.Log("IP was parsed as CIDR")
			} else if ip.Mask != nil {
				t.Log("IP was parsed as IP range")
			}
		} else if literal.Address.Text != nil && literal.Address.Text.Direct != nil {
			// FAILURE: The value was captured as Text instead of being parsed as IP
			// This is the actual flaw - quoted strings like "{ 2.3.4.5 }" are parsed as Text
			t.Errorf("PARSER FLAW: Variable value is captured as Address.Text: %q\n"+
				"The quoted string \"{ 2.3.4.5 }\" is being parsed as a Text value instead of "+
				"being recognized as a brace list containing an IP address.\n"+
				"Expected: the IP address 2.3.4.5 to be accessible via literal.Address.IP.Direct.Address",
				literal.Address.Text.Direct.Value)
		} else if literal.String.Direct != nil {
			// FAILURE: The value was captured as a string instead of being parsed as IP
			t.Errorf("PARSER FLAW: Variable value is only accessible as string: %q, "+
				"expected the IP address 2.3.4.5 to be accessible via literal.Address.IP",
				literal.String.Direct.Value)
		} else {
			t.Errorf("Unexpected literal structure: Address.IP=%+v, Address.Text=%+v, String=%+v, Number=%+v",
				literal.Address.IP, literal.Address.Text, literal.String, literal.Number)
		}
	})

	t.Run("variable without braces should parse IP directly", func(t *testing.T) {
		// Test case where variable is assigned without braces - this should work
		input := `simple_ip = 2.3.4.5`

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "failed to parse configuration")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1, "expected 1 line")

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment, "line should be an assignment")
		assert.Equal(t, "simple_ip", assignment.Variable)

		require.NotEmpty(t, assignment.Value.Values, "assignment should have values")
		firstValue := assignment.Value.Values[0]
		require.NotNil(t, firstValue.Direct, "value should be parsed directly")

		literal := firstValue.Direct

		// This should be parsed as an Address with IP
		require.NotNil(t, literal.Address.IP, "literal should have an IP address")
		require.NotNil(t, literal.Address.IP.Direct, "IP should be direct, not a variable")
		require.NotNil(t, literal.Address.IP.Direct.Address, "IP should be an address")

		expectedIP := netip.MustParseAddr("2.3.4.5")
		assert.Equal(t, expectedIP, *literal.Address.IP.Direct.Address, "IP address should be 2.3.4.5")
	})

	t.Run("variable with brace list should parse multiple IPs", func(t *testing.T) {
		// Test case with explicit brace list in PF syntax (not quoted string)
		input := `multi_ip = { 1.2.3.4, 5.6.7.8 }`

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "failed to parse configuration")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1, "expected 1 line")

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment, "line should be an assignment")
		assert.Equal(t, "multi_ip", assignment.Variable)

		// For brace list, we expect multiple values
		require.Len(t, assignment.Value.Values, 2, "assignment should have 2 values from brace list")

		// First IP
		firstValue := assignment.Value.Values[0]
		require.NotNil(t, firstValue.Direct, "first value should be parsed directly")
		require.NotNil(t, firstValue.Direct.Address.IP, "first value should have IP")
		require.NotNil(t, firstValue.Direct.Address.IP.Direct, "first IP should be direct")
		require.NotNil(t, firstValue.Direct.Address.IP.Direct.Address, "first IP should be address")
		assert.Equal(t, netip.MustParseAddr("1.2.3.4"), *firstValue.Direct.Address.IP.Direct.Address)

		// Second IP
		secondValue := assignment.Value.Values[1]
		require.NotNil(t, secondValue.Direct, "second value should be parsed directly")
		require.NotNil(t, secondValue.Direct.Address.IP, "second value should have IP")
		require.NotNil(t, secondValue.Direct.Address.IP.Direct, "second IP should be direct")
		require.NotNil(t, secondValue.Direct.Address.IP.Direct.Address, "second IP should be address")
		assert.Equal(t, netip.MustParseAddr("5.6.7.8"), *secondValue.Direct.Address.IP.Direct.Address)
	})
}

func Test_VariableReference_StartingWithDigit(t *testing.T) {
	input := `pass in log quick proto tcp from <v_d_3_hosts> to $3_d_v_109 port 9701 rdr-to $waf_p_106`

	conf, err := parser.ParseContent(input)
	require.NoError(t, err, "rule with digit-leading macro reference should parse")
	require.NotNil(t, conf)
	require.Len(t, conf.Line, 1)
	require.NotNil(t, conf.Line[0].PfRule)
}

func TestAssignmentInterfaceModifierValue(t *testing.T) {
	input := "pfsync_net   = vlan3:network\n"

	conf, err := parser.ParseContent(input)
	require.NoError(t, err, "assignment with interface modifier value should parse")
	require.NotNil(t, conf)
	require.Len(t, conf.Line, 1)

	assignment := conf.Line[0].Assignment
	require.NotNil(t, assignment)
	require.Equal(t, "pfsync_net", assignment.Variable)
	require.NotNil(t, assignment.InterfaceWithModifier)
	require.Equal(t, "vlan3", assignment.InterfaceWithModifier.Interface)
	require.Equal(t, "network", assignment.InterfaceWithModifier.Modifier)
}

func TestAssignmentNameStartingWithDigit(t *testing.T) {
	input := "3_d_v_109      = 10.0.1.10\n"

	conf, err := parser.ParseContent(input)
	require.NoError(t, err, "assignment name starting with digit should parse")
	require.NotNil(t, conf)
	require.Len(t, conf.Line, 1)

	assignment := conf.Line[0].Assignment
	require.NotNil(t, assignment)
	require.Equal(t, "3_d_v_109", assignment.Variable)
	require.NotEmpty(t, assignment.Value.Values)
}
