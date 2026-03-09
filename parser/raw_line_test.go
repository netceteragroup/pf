package parser_test

import (
	"testing"

	"github.com/RogueTeam/pf/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Line_RawText(t *testing.T) {
	t.Run("single pass rule preserves original text", func(t *testing.T) {
		input := "pass log quick proto tcp from <some_table>        to $some_var               port 50102\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		expected := "pass log quick proto tcp from <some_table>        to $some_var               port 50102"
		assert.Equal(t, expected, conf.Line[0].RawText(), "RawText() should return the original configuration line")
	})

	t.Run("multiple lines each preserve their original text", func(t *testing.T) {
		input := `some_net = "192.168.0.96/27 192.168.1.192/26"
table <some_hosts> { $some_net }
pass log quick proto tcp  from $some_host      to <some_hosts>        port { 443 6556 }
`

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 3)

		assert.Equal(t, `some_net = "192.168.0.96/27 192.168.1.192/26"`, conf.Line[0].RawText())
		assert.Equal(t, "table <some_hosts> { $some_net }", conf.Line[1].RawText())
		assert.Equal(t, "pass log quick proto tcp  from $some_host      to <some_hosts>        port { 443 6556 }", conf.Line[2].RawText())
	})

	t.Run("comment line preserves original text", func(t *testing.T) {
		input := "# This is a comment\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assert.Equal(t, "# This is a comment", conf.Line[0].RawText())
	})

	t.Run("block rule preserves original text", func(t *testing.T) {
		input := "block return in on ! lo0 proto tcp to port 6000:6010\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assert.Equal(t, "block return in on ! lo0 proto tcp to port 6000:6010", conf.Line[0].RawText())
	})

	t.Run("set option preserves original text", func(t *testing.T) {
		input := "set skip on lo\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assert.Equal(t, "set skip on lo", conf.Line[0].RawText())
	})

	t.Run("mixed config with comments and rules", func(t *testing.T) {
		input := `# firewall rules
set skip on lo
block all
pass in on egress proto tcp to port 22
`

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 4)

		assert.Equal(t, "# firewall rules", conf.Line[0].RawText())
		assert.Equal(t, "set skip on lo", conf.Line[1].RawText())
		assert.Equal(t, "block all", conf.Line[2].RawText())
		assert.Equal(t, "pass in on egress proto tcp to port 22", conf.Line[3].RawText())
	})

	t.Run("include directive preserves original text", func(t *testing.T) {
		input := `include "/etc/pf/rules.conf"
`

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assert.Equal(t, `include "/etc/pf/rules.conf"`, conf.Line[0].RawText())
	})

	t.Run("assignment preserves original text with whitespace", func(t *testing.T) {
		input := `ext_if    =    "egress"
`

		conf, err := parser.ParseContent(input)
		require.NoError(t, err)
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assert.Equal(t, `ext_if    =    "egress"`, conf.Line[0].RawText())
	})
}
