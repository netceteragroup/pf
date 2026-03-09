package parser_test

import (
	"net/netip"
	"testing"

	"github.com/RogueTeam/pf/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MultilineString(t *testing.T) {
	t.Run("variable with backslash-newline continuation in quoted string", func(t *testing.T) {
		input := "big_list = \"{ 3.5.140.0/22 52.219.170.0/23 \\\n\t52.95.150.0/24 52.219.60.0/23 }\"\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle multiline quoted strings with backslash-newline")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment, "line should be an assignment")
		require.Equal(t, "big_list", assignment.Variable)

		// The quoted list should be parsed and CIDRs extracted
		require.NotEmpty(t, assignment.Value.Values)
		literal := assignment.Value.Values[0].Direct
		require.NotNil(t, literal)
		require.NotNil(t, literal.QuotedBraceList, "should be parsed as QuotedBraceList")
		assert.Len(t, literal.QuotedBraceList.Prefixes, 4, "expected 4 CIDR prefixes")
		assert.Equal(t, netip.MustParsePrefix("3.5.140.0/22"), literal.QuotedBraceList.Prefixes[0])
		assert.Equal(t, netip.MustParsePrefix("52.219.170.0/23"), literal.QuotedBraceList.Prefixes[1])
		assert.Equal(t, netip.MustParsePrefix("52.95.150.0/24"), literal.QuotedBraceList.Prefixes[2])
		assert.Equal(t, netip.MustParsePrefix("52.219.60.0/23"), literal.QuotedBraceList.Prefixes[3])
	})

	t.Run("full multiline example matching the reported issue", func(t *testing.T) {
		input := "big_list               = \"{ 3.5.140.0/22 52.219.170.0/23 52.219.168.0/24 16.12.80.0/24 \\\n" +
			"\t\t\t\t\t\t\t52.95.150.0/24 52.219.60.0/23 3.5.60.0/22 16.12.44.0/24 16.12.6.0/23 16.12.32.0/22 52.219.204.0/22 }\"\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle the exact multiline example from the issue")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment)
		require.Equal(t, "big_list", assignment.Variable)
		require.NotEmpty(t, assignment.Value.Values)

		literal := assignment.Value.Values[0].Direct
		require.NotNil(t, literal)
		require.NotNil(t, literal.QuotedBraceList)
		assert.Len(t, literal.QuotedBraceList.Prefixes, 11, "expected 11 CIDR prefixes")
	})

	t.Run("multiline rule continuation outside quoted strings", func(t *testing.T) {
		input := "pass log quick proto tcp \\\n\tfrom any to any port 22\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle multiline rule continuation")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		pfRule := conf.Line[0].PfRule
		require.NotNil(t, pfRule, "line should be a PF rule")
		assert.True(t, bool(pfRule.Action.Pass))
	})

	t.Run("multiple continuations in one definition", func(t *testing.T) {
		input := "big_list = \"{ 10.0.0.0/8 \\\n\t172.16.0.0/12 \\\n\t192.168.0.0/16 }\"\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle multiple continuations")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment)
		require.Equal(t, "big_list", assignment.Variable)
		require.NotEmpty(t, assignment.Value.Values)

		literal := assignment.Value.Values[0].Direct
		require.NotNil(t, literal)
		require.NotNil(t, literal.QuotedBraceList)
		assert.Len(t, literal.QuotedBraceList.Prefixes, 3, "expected 3 CIDR prefixes")
	})

	t.Run("bigger multiline list", func(t *testing.T) {
		input := "bigger_list = \"{ 20.84.138.56 20.84.138.65 20.84.139.83 20.84.139.106 \\\n                         20.84.139.123 20.84.139.126 20.84.139.199 20.84.139.204 20.84.139.224 20.84.139.229 20.84.140.61 20.84.136.30 20.84.136.31 20.84.136.88 20.84.136.89 \\\n                         20.84.136.104 20.84.136.105 20.84.136.108 20.84.136.109 20.84.136.140 20.84.136.141 20.84.136.166 20.84.136.167 20.84.136.174 20.118.56.2 20.85.22.240 \\\n                         20.85.22.247 20.85.23.14 20.85.21.245 20.85.23.35 20.85.23.36 20.119.128.0 20.85.22.206 20.85.22.209 20.85.22.211 20.85.22.221 20.85.22.228 20.85.22.231 \\\n                         20.85.22.240 20.85.22.247 20.85.23.14 20.85.21.245 20.85.23.35 20.85.23.36 20.72.94.234 20.85.23.66 20.85.23.80 20.85.23.98 20.85.23.240 20.85.17.130 \\\n                         20.85.23.246 20.94.120.17 20.94.120.27 20.94.120.44 20.94.120.50 20.85.22.85 20.119.128.0 20.53.141.141 20.53.141.191 20.53.141.233 20.53.74.19 20.53.142.93 \\\n                         20.53.142.211 20.37.196.202 20.53.139.30 20.53.141.20 20.53.141.30 20.53.141.39 20.53.141.78 20.53.141.81 20.53.141.141 20.53.141.191 20.53.141.233 \\\n                         20.53.74.19 20.53.142.93 20.53.142.211 20.53.142.233 20.53.105.77 20.53.143.83 20.53.143.159 20.53.143.182 20.53.90.155 20.53.160.18 20.53.160.63 20.53.160.86 \\\n                         20.53.140.86 20.53.160.95 20.53.160.112 20.37.196.202 52.243.86.237 52.243.76.46 52.243.72.114 52.189.239.27 52.243.79.209 13.77.50.97 52.243.77.20 \\\n                         52.243.86.237 52.243.76.46 52.243.72.114 52.189.239.27 52.243.79.209 20.108.231.32 20.108.131.119 20.108.231.40 20.108.231.43 20.108.226.194 20.108.225.1 \\\n                         20.90.134.11 20.108.229.103 20.108.230.168 20.108.230.243 20.108.230.145 20.108.226.93 20.108.230.128 20.108.231.32 20.108.131.119 20.108.231.40 20.108.231.43 \\\n                         20.108.226.194 20.108.225.1 20.108.225.152 20.108.226.243 20.108.230.206 20.108.230.208 20.108.228.85 20.108.231.51 20.108.230.90 20.90.246.59 20.90.246.139 \\\n                         20.90.247.51 20.90.247.219 20.108.96.0 20.90.134.11 51.140.243.28 51.141.118.176 51.140.247.165 51.140.219.138 51.140.201.163 51.140.210.99 51.141.121.252 \\ \n                         51.141.30.11 51.140.216.188 51.140.218.72 51.140.243.28 51.141.118.176 51.140.247.165 51.140.219.138 51.140.201.163 175.45.81.140 52.147.47.48/28 20.43.105.176/28 20.53.137.112/28 \\\n                         98.100.114.129 206.55.116.215 162.254.124.215 162.254.126.129 4.198.64.222 20.70.111.87 20.70.111.96 20.11.137.116 20.11.140.9 20.70.107.94 20.11.137.82 20.11.129.166 20.92.42.146 \\\n                         20.70.74.136 20.11.132.42 20.70.78.96 20.92.40.107 }\"\n"

		conf, err := parser.ParseContent(input)
		require.NoError(t, err, "parser should handle multiple continuations")
		require.NotNil(t, conf)
		require.Len(t, conf.Line, 1)

		assignment := conf.Line[0].Assignment
		require.NotNil(t, assignment)
		require.Equal(t, "bigger_list", assignment.Variable)
		require.NotEmpty(t, assignment.Value.Values)

		literal := assignment.Value.Values[0].Direct
		require.NotNil(t, literal)
		require.NotNil(t, literal.QuotedBraceList)
		assert.Len(t, literal.QuotedBraceList.Prefixes, 3, "expected 3 CIDR prefixes")
	})
}
