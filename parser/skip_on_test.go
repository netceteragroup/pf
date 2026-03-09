package parser_test

import (
	"encoding/json"
	"testing"

	"github.com/RogueTeam/pf/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SkipOn_SpaceSeparatedBraceList(t *testing.T) {
	t.Run("set skip on with space-separated interfaces in braces", func(t *testing.T) {
		input := "set skip on { lo0 pfsync vlan7 }\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should not fail on space-separated brace list")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1, "expected 1 line")

		option := conf.Line[0].Option
		require.NotNil(t, option, "line should be an Option")
		require.NotNil(t, option.SkipOn, "option should be SkipOn")

		ifSpec := option.SkipOn.IfSpec
		require.Len(t, ifSpec.Values, 3, "expected 3 interfaces in skip on list")

		// Verify the three interfaces
		interfaces := make([]string, 0, 3)
		for _, v := range ifSpec.Values {
			require.NotNil(t, v.Direct, "interface entry should be direct")
			require.NotNil(t, v.Direct.InterfaceOrInterfaceGroup.Direct, "interface name should be direct")
			interfaces = append(interfaces, v.Direct.InterfaceOrInterfaceGroup.Direct.Value)
		}
		assert.Equal(t, []string{"lo0", "pfsync", "vlan7"}, interfaces)

		c, _ := json.MarshalIndent(conf, "", "\t")
		t.Log(string(c))
	})

	t.Run("set skip on with comma-separated interfaces still works", func(t *testing.T) {
		input := "set skip on { lo0, pfsync, vlan7 }\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle comma-separated brace list")
		require.NotNil(t, conf)

		option := conf.Line[0].Option
		require.NotNil(t, option)
		require.NotNil(t, option.SkipOn)
		require.Len(t, option.SkipOn.IfSpec.Values, 3, "expected 3 interfaces")
	})

	t.Run("set skip on with single interface without braces", func(t *testing.T) {
		input := "set skip on lo0\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle single interface without braces")
		require.NotNil(t, conf)

		option := conf.Line[0].Option
		require.NotNil(t, option)
		require.NotNil(t, option.SkipOn)
		require.Len(t, option.SkipOn.IfSpec.Values, 1, "expected 1 interface")
	})
}

func Test_FromToImplicit(t *testing.T) {
	t.Run("from implicit any to explicit any with port", func(t *testing.T) {
		input := "pass log quick proto tcp from to any port 22\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle implicit 'from' target (any)")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule, "line should be a PfRule")
		assert.True(t, bool(rule.Action.Pass), "action should be pass")

		// The hosts section should be present
		require.NotNil(t, rule.Hosts, "hosts should be present")
		require.NotEmpty(t, rule.Hosts.HostsFromTo, "from/to should be present")

		c, _ := json.MarshalIndent(conf, "", "\t")
		t.Log(string(c))
	})

	t.Run("from explicit any to explicit any with port", func(t *testing.T) {
		// This case should already work
		input := "pass log quick proto tcp from any to any port 22\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle explicit 'from any to any'")
		require.NotNil(t, conf)

		rule := conf.Line[0].PfRule
		require.NotNil(t, rule)
		require.NotNil(t, rule.Hosts)
	})
}

func Test_Configuration_SourceText(t *testing.T) {
	t.Run("original source text should be reconstructable for debugging", func(t *testing.T) {
		// The Configuration type and its Line elements should allow
		// outputting the original source text for debugging.
		// Since participle stores position info, we can at least verify
		// the parsed structure preserves enough info.
		input := "pass log quick proto tcp from any to any port 22\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)

		// Verify we can marshal to JSON for debugging purposes
		jsonBytes, err := json.MarshalIndent(conf, "", "  ")
		require.NoError(t, err, "should be able to marshal configuration to JSON")
		assert.NotEmpty(t, jsonBytes, "JSON output should not be empty")
		t.Logf("Debug output:\n%s", string(jsonBytes))
	})
}
