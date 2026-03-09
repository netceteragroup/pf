package parser_test

import (
	"testing"

	"github.com/RogueTeam/pf/parser"
	"github.com/stretchr/testify/require"
)

func Test_SetTimeoutSrcTrack(t *testing.T) {
	input := "set timeout src.track 30\n"

	conf, err := parser.ParseContent(input)
	require.NoError(t, err, "set timeout src.track should parse")
	require.NotNil(t, conf)
	require.Len(t, conf.Line, 1)
	require.NotNil(t, conf.Line[0].Option)
	require.NotNil(t, conf.Line[0].Option.Timeout)
	require.Equal(t, "src.track", conf.Line[0].Option.Timeout.Timeout.Values[0].Direct.Variable)
	require.NotNil(t, conf.Line[0].Option.Timeout.Timeout.Values[0].Direct.Value.Direct)
	require.Equal(t, 30, conf.Line[0].Option.Timeout.Timeout.Values[0].Direct.Value.Direct.Value)
}
