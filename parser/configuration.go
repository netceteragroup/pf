// Check references: https://man.openbsd.org/pf.conf#EXAMPLES
package parser

import (
	"net/netip"
	"strings"

	"github.com/alecthomas/participle/v2/lexer"
	"go4.org/netipx"
)

type (
	Timeout struct {
		Variable string        `parser:"@('tcp.first' | 'tcp.opening' | 'tcp.established' | 'tcp.closing' | 'tcp.finwait' | 'tcp.closed' | 'tcp.tsdiff' | 'udp.first' | 'udp.single' | 'udp.multiple' | 'icmp.first' | 'icmp.error' | 'other.first' | 'other.single' | 'other.multiple' | 'frag' | 'interval' | 'src.track' | 'adaptive.start' | 'adaptive.end')"`
		Value    Value[Number] `parser:"@@"`
	}
	TimeoutOption struct {
		Timeout ValueOrBraceList[Timeout] `parser:"'timeout' @@"`
	}
	RulesetOptimizationOption struct {
		Value string `parser:"'ruleset-optimization' @('none' | 'basic' | 'profile')"`
	}
	OptimizatioOption struct {
		Value string `parser:"'optimization' @('default' | 'normal' | 'high-latency' | 'satellite' | 'aggressive' | 'convervative')"`
	}
	LimitItem struct {
		Variable string        `parser:"@('states' | 'frags' | 'src-nodes' | 'tables' | 'table-entries')"`
		Value    Value[Number] `parser:"@@"`
	}
	LimitOption struct {
		Limit ValueOrBraceList[LimitItem] `parser:"'limit' @@"`
	}
	LoginInterfaceOption struct {
		None      BooleanSet  `parser:"'logininterface' ( @('none')"`
		Interface Value[Text] `parser:"| @@)"`
	}
	BlockPolicyOption struct {
		Policy string `parser:"'block-policy' @('drop' | 'return')"`
	}
	StatePolicyOption struct {
		Policy string `parser:"'state-policy' @('if-bound' | 'floating')"`
	}
	FlushStateOverloadEntry struct {
		Global BooleanSet `parser:"'flush' @('global')?"`
	}
	StateOverloadEntry struct {
		Value Value[Text]              `parser:"'overload' '<' @@ '>'"`
		Flush *FlushStateOverloadEntry `parser:"@@?"`
	}
	MaxSrcConnRateCompact struct {
		Value string `parser:"@AbbrevCIDR"`
	}
	MaxSrcConnRage struct {
		Packets Value[Number]          `parser:"'max-src-conn-rate' ( @@"`
		Seconds Value[Number]          `parser:"'/' @@ )"`
		Compact *MaxSrcConnRateCompact `parser:"| ('max-src-conn-rate' @@)"`
	}
	StateOption struct {
		Max            *Value[Number]      `parser:"('max' @@)"`
		NoSync         BooleanSet          `parser:"| @('no-sync')"`
		Timeout        *Timeout            `parser:"| @@"`
		Sloppy         BooleanSet          `parser:"| @('sloppy')"`
		Pflow          BooleanSet          `parser:"| @('pflow')"`
		SourceTrack    string              `parser:"| ('source-track' @('rule' | 'global'))"`
		MaxSrcNodes    *Value[Number]      `parser:"| ('max-src-nodes' @@)"`
		MaxSrcStates   *Value[Number]      `parser:"| ('max-src-states' @@)"`
		MaxSrcConn     *Value[Number]      `parser:"| ('max-src-conn' @@)"`
		MaxSrcConnRate *MaxSrcConnRage     `parser:"| @@"`
		Overload       *StateOverloadEntry `parser:"| @@"`
		IfFloating     BooleanSet          `parser:"| @('if-floating')"`
		Floating       BooleanSet          `parser:"| @('floating')"`
	}
	StateDefaultsOption struct {
		Defaults ValueOrRawList[StateOption] `parser:"'state-defaults' @@"`
	}
	FingerPrintsOption struct {
		Filename Value[Text] `parser:"'fingerprints' @@"`
	}
	IfSpecEntry struct {
		Negate                    BooleanSet  `parser:"'!'?"`
		InterfaceOrInterfaceGroup Value[Text] `parser:"@@"`
	}
	IfSpec       ValueOrBraceList[IfSpecEntry]
	SkipOnOption struct {
		IfSpec IfSpec `parser:"'skip' 'on' @@"`
	}
	DebugOption struct {
		Level string `parser:"'debug' @('urgent' | 'emerg' | 'alert' | 'crit' | 'err' | 'warning' | 'notice' | 'info' | 'debug')"`
	}
	ReassembleOption struct {
		Reassemble BooleanSet `parser:"'reassemble' (@('yes') | 'no')"`
		NoDf       BooleanSet `parser:"@('no-df')?"`
	}
	OtherOption struct {
		Key   string         `parser:"@Ident"`
		Value Value[Literal] `parser:"@@"`
	}
	SyncookiesAdaptive struct {
		Start Value[Number] `parser:"'(' 'start' @@ '%' ','"`
		End   Value[Number] `parser:"'end' @@ '%' ')'"`
	}
	SyncookiesOption struct {
		Mode     string              `parser:"'syncookies' @('never' | 'always' | 'adaptive')"`
		Adaptive *SyncookiesAdaptive `parser:"@@?"`
	}
	Option struct {
		Timeout             *TimeoutOption             `parser:"'set' (@@"`
		RulesetOptimization *RulesetOptimizationOption `parser:"| @@"`
		Optimizatio         *OptimizatioOption         `parser:"| @@"`
		Limit               *LimitOption               `parser:"| @@"`
		BlockPolicy         *BlockPolicyOption         `parser:"| @@"`
		StatePolicy         *StatePolicyOption         `parser:"| @@"`
		StateDefaults       *StateDefaultsOption       `parser:"| @@"`
		FingerPrints        *FingerPrintsOption        `parser:"| @@"`
		SkipOn              *SkipOnOption              `parser:"| @@"`
		Debug               *DebugOption               `parser:"| @@"`
		Reassemble          *ReassembleOption          `parser:"| @@"`
		Syncookies          *SyncookiesOption          `parser:"| @@"`
		Other               *OtherOption               `parser:"| @@)"`
	}
	ActionBlockReturn struct {
		Return string `parser:"@('return' | 'drop')"`
	}
	ActionBlock struct {
		Return *string `parser:"'block' @('return' | 'return-icmp' | 'return-icmp6' | 'return-rst' | 'drop')?"`
	}
	Action struct {
		Pass  BooleanSet   `parser:"@('pass')"`
		Match BooleanSet   `parser:"| @('match')"`
		Block *ActionBlock `parser:"| @@"`
	}
	LogOption struct {
		All     BooleanSet   `parser:"@('all')"`
		Matches BooleanSet   `parser:"| @('matches')"`
		User    BooleanSet   `parser:"| @('user')"`
		To      *Value[Text] `parser:"| ('to' @@)"`
	}
	Log struct {
		Options *ValueOrRawList[LogOption] `parser:"'log' ('(' @@ ')')?"`
	}
	PfRuleOn struct {
		IfSpec  *IfSpec        `parser:"'on' ( @@"`
		Rdomain *Value[Number] `parser:"| ('rdomain' @@))"`
	}
	AddressFamily struct {
		Is4 BooleanSet `parser:"@('inet') | 'inet6'"`
	}
	Protocol struct {
		Name   *Value[Text]   `parser:"@@"`
		Number *Value[Number] `parser:"| @@"`
	}
	ProtoSpec struct {
		Protocol ValueOrBraceList[Protocol] `parser:"'proto' @@"`
	}
	IP struct {
		Mask       *netipx.IPRange  `parser:"@IPRange"`
		CIDR       *netip.Prefix    `parser:"| @CIDR"`
		AbbrevCIDR *AbbreviatedCIDR `parser:"| @AbbrevCIDR"`
		Address    *netip.Addr      `parser:"| @Address"`
	}
	Address struct {
		IP                    *Value[IP]                    `parser:"@@"`
		UrpfFailed            BooleanSet                    `parser:"| @('urpf-failed')"`
		InterfaceWithModifier *InterfaceWithModifierLiteral `parser:"| @@"`
		Text                  *Value[Text]                  `parser:"| @@"`
	}
	Host struct {
		Negate            BooleanSet     `parser:"@('!')?"`
		ParenInterface    *Value[Text]   `parser:"( ('(' @@"`
		InterfaceModifier *string        `parser:"(':' @('0' | 'broadcast' | 'network' | 'peer'))? ')')"`
		Address           *Address       `parser:"| ( @@"`
		Weight            *Value[Number] `parser:"('weight' @@)? )"`
		AsString          *Value[Text]   `parser:"| ('<' @@ '>') )"`
	}
	Unary struct {
		Operator string         `parser:"@('=' | '!=' | '<' | '<=' | '>' | '>=')?"`
		Number   *Value[Number] `parser:"( @@ "`
		Name     *Value[Text]   `parser:"| @@ )"`
	}
	Binary struct {
		Lhs      Value[Number] `parser:"@@"`
		Operator string        `parser:"@(':' | '<>' | '><')"`
		Rhs      Value[Number] `parser:"@@"`
	}
	Operation struct {
		Binary *Binary `parser:"@@"`
		Unary  *Unary  `parser:"| @@"`
	}
	Port struct {
		Ports ValueOrBraceList[Operation] `parser:"'port' @@"`
	}
	Os struct {
		Selected ValueOrBraceList[Value[Text]] `parser:"'os' @@"`
	}
	HostsTarget struct {
		Any     BooleanSet   `parser:"( @('any')"`
		NoRoute BooleanSet   `parser:"| @('no-route')"`
		Self    BooleanSet   `parser:"| @('self')"`
		Route   *Value[Text] `parser:"| ('route' @@)"`
		Host    *Host        `parser:"| @@ )"`
	}
	HostFromFirstPort struct {
		Port *Port `parser:"'from' @@"`
		Os   *Os   `parser:"@@?"`
	}
	HostFromFirstOs struct {
		Os *Os `parser:"'from' @@"`
	}
	HostFrom struct {
		FirstPort   *HostFromFirstPort             `parser:"@@"`
		FirstOs     *HostFromFirstOs               `parser:"| @@"`
		ImplicitAny BooleanSet                     `parser:"| ( @('from') (?= 'to')"`
		Port        *Port                          `parser:"@@?"`
		Os          *Os                            `parser:"@@? )"`
		Target      *ValueOrBraceList[HostsTarget] `parser:"| ('from' @@"`
		Port2       *Port                          `parser:"@@?"`
		Os2         *Os                            `parser:"@@? )"`
	}
	HostTo struct {
		OnlyPort *Port                          `parser:"  ('to' @@)"`
		Target   *ValueOrBraceList[HostsTarget] `parser:"| ('to' @@"`
		Port     *Port                          `parser:"@@?)"`
	}
	HostsFromTo struct {
		From *HostFrom `parser:"@@"`
		To   *HostTo   `parser:"| @@"`
	}
	Hosts struct {
		All         BooleanSet     `parser:"@('all')"`
		HostsFromTo []*HostsFromTo `parser:"| @@+"`
	}
	User struct {
		Selected ValueOrBraceList[Operation] `parser:"'user' @@"`
	}
	Group struct {
		Selected ValueOrBraceList[Operation] `parser:"'group' @@"`
	}
	Flags struct {
		Left  []string   `parser:"'flags' @Ident?"`
		Right string     `parser:"'/' (@Ident"`
		Any   BooleanSet `parser:"@('any')? )"`
	}
	IcmpCode struct {
		Name         *Value[Text]   `parser:"( @@"`
		Number       *Value[Number] `parser:"| @@)"`
		CodeAsName   *Value[Text]   `parser:"( 'code' (@@"`
		CodeAsNumber *Value[Number] `parser:"| @@) )?"`
	}
	IcmpType struct {
		Codes ValueOrBraceList[IcmpCode] `parser:"'icmp-type' @@"`
	}
	IcmpType6 struct {
		Codes ValueOrBraceList[IcmpCode] `parser:"'icmp6-type' @@"`
	}
	Tos struct {
		Selected string `parser:"@('lowdelay' | 'throughput' | 'reliability')"`
		Number   int    `parser:"@Hexnumber"`
	}
	Label struct {
		Text Value[Text] `parser:"'label' @@"`
	}
	Tag struct {
		Text Value[Text] `parser:"'tag' @@"`
	}
	Tagged struct {
		Negate BooleanSet  `parser:"@('!')?"`
		Text   Value[Text] `parser:"'tagged' @@"`
	}
	ScrubOption struct {
		NoDf          BooleanSet     `parser:"@('no-df')"`
		MinTtl        *Value[Number] `parser:"| ('min-ttl' @@)"`
		MaxMss        *Value[Number] `parser:"| ('max-mss' @@)"`
		ReassembleTcp BooleanSet     `parser:"| @('reassemble' 'tcp')"`
		RandomId      BooleanSet     `parser:"| @('random-id')"`
	}
	ScrubOptions struct {
		Options ValueOrRawList[ScrubOption] `parser:"@@"`
	}
	State struct {
		Mode    *string                      `parser:"@('no' | 'keep' | 'modulate' | 'synproxy') 'state'"`
		Options *ValueOrRawList[StateOption] `parser:"('(' @@ ')')?"`
	}
	DivertTo struct {
		Host Host `parser:"'divert-to' @@"`
		Port Port `parser:"'port' @@"`
	}
	MaxPacketRate struct {
		Packets Value[Number]  `parser:"'max-pkt-rate' @@"`
		Seconds *Value[Number] `parser:"('/' @@)?"`
	}
	AfTo struct {
		AddressFamily AddressFamily           `parser:"'af-to' @@"`
		From          ValueOrBraceList[Host]  `parser:"'from' @@"`
		To            *ValueOrBraceList[Host] `parser:"('to' @@)?"`
	}
	PortSpec struct {
		Name             *Value[Text]   `parser:"'port' ( @@"`
		Number           *Value[Number] `parser:"| @@ )"`
		RangedToWildcard BooleanSet     `parser:"(':' ( @('*')"`
		RangedToNumber   *Value[Number] `parser:"| @@"`
		RangedToName     *Value[Text]   `parser:"| @@ ))?"`
	}
	SourceHash struct {
		Value *Value[Text] `parser:"'source-hash' @@?"`
	}
	PoolType struct {
		Bitmask       BooleanSet  `parser:"@('bitmask')"`
		LeastStates   BooleanSet  `parser:"| @('least-states')"`
		Random        BooleanSet  `parser:"| @('random')"`
		RoundRobin    BooleanSet  `parser:"| @('round-robin')"`
		SourceHash    *SourceHash `parser:"| @@"`
		StickyAddress BooleanSet  `parser:"| @('sticky-address')"`
	}
	BinAtTo struct {
		To       ValueOrBraceList[Host] `parser:"'binat-to' @@"`
		PortSpec *PortSpec              `parser:"@@?"`
		PoolType *PoolType              `parser:"@@?"`
	}
	RdrTo struct {
		Host     ValueOrBraceList[Host] `parser:"'rdr-to' @@"`
		PortSpec *PortSpec              `parser:"@@?"`
		PoolType *PoolType              `parser:"@@?"`
	}
	NatTo struct {
		Host       ValueOrBraceList[Host] `parser:"'nat-to' @@"`
		PortSpec   *PortSpec              `parser:"@@?"`
		PoolType   *PoolType              `parser:"@@?"`
		StaticPort BooleanSet             `parser:"@('static-port')?"`
	}

	FilterOption struct {
		User             *User            `parser:"@@"`
		Group            *Group           `parser:"| @@"`
		Flags            *Flags           `parser:"| @@"`
		IcmpType         *IcmpType        `parser:"| @@"`
		IcmpType6        *IcmpType6       `parser:"| @@"`
		Tos              *Tos             `parser:"| ('tos' @@)"`
		State            *State           `parser:"| @@"`
		ScrubOption      *ScrubOptions    `parser:"| ('scrub' '(' @@ ')')"`
		Fragment         BooleanSet       `parser:"| @('fragment')"`
		AllowOpts        BooleanSet       `parser:"| @('allow-opts')"`
		Once             BooleanSet       `parser:"| @('once')"`
		DivertPacketPort *Port            `parser:"| ('divert-packet' @@)"`
		DivertReply      BooleanSet       `parser:"| @('divert-reply')"`
		DivertTo         DivertTo         `parser:"| @@"`
		Label            *Label           `parser:"| @@"`
		Tag              *Tag             `parser:"| @@"`
		Tagged           *Tagged          `parser:"| @@"`
		MaxPacketRate    *MaxPacketRate   `parser:"| @@"`
		SetDelay         *Value[Number]   `parser:"| ('set' 'delay' @@)"`
		SetPrio          *[]Value[Number] `parser:"| ('set' 'prio'  (@@ | '(' @@ (',' @@)* ')' ))"`
		SetQueue         *[]Value[Text]   `parser:"| ('set' 'queue' (@@ | '(' @@ (',' @@)* ')' ))"`
		Rtable           *Value[Number]   `parser:"| ('rtable' @@)"`
		Probability      *Value[Number]   `parser:"| ('probability' @@ '%')"`
		Prio             *Value[Number]   `parser:"| ('prio' @@)"`
		AfTo             *AfTo            `parser:"| @@"`
		BinAtTo          *BinAtTo         `parser:"| @@"`
		RdrTo            *RdrTo           `parser:"| @@"`
		NatTo            *NatTo           `parser:"| @@"`
		// [ route ]: Specifies a routing action.
		// [ "set tos" tos ]: Sets the Type of Service (TOS) field in the IP header.
		// [ [ "!" ] "received-on" ( interface-name | interface-group ) ]: Matches packets received on a specific interface or interface group, optionally negated.
	}
	PfRuleOption struct {
		Direction     *string        `parser:"@('in' | 'out')"`
		Log           *Log           `parser:"| @@"`
		Quick         BooleanSet     `parser:"| @('quick')"`
		On            *PfRuleOn      `parser:"| @@"`
		AddressFamily *AddressFamily `parser:"| @@"`
		ProtoSpec     *ProtoSpec     `parser:"| @@"`
	}
	PfRule struct {
		Action        Action                        `parser:"@@"`
		Options       []*PfRuleOption               `parser:"@@*"`
		Hosts         *Hosts                        `parser:"@@?"`
		FilterOptions *ValueOrRawList[FilterOption] `parser:"@@?"`
	}
	AntiSpoofRule struct {
		Log           *Log           `parser:"'antispoof' @@?"`
		Quick         BooleanSet     `parser:"@('quick')?"`
		IfSpec        IfSpec         `parser:"'for' @@"`
		AddressFamily *AddressFamily `parser:"@@?"`
		Label         *Label         `parser:"@@?"`
	}
	InterfaceWithModifierLiteral struct {
		Interface string `parser:"@(Ident | Hostname | Filename)"`
		Modifier  string `parser:"':' @('0' | 'broadcast' | 'network' | 'peer')"`
	}
	Literal struct {
		QuotedBraceList *QuotedLiteralList `parser:"@String"`
		Address         Address            `parser:"| @@"`
		String          Value[Text]        `parser:"| @@"`
		Number          Value[Number]      `parser:"| @@"`
	}
	Include struct {
		Filename Value[Text] `parser:"'include' @@"`
	}
	Assignment struct {
		Variable              string                         `parser:"@(Ident | MacroIdent)"`
		InterfaceWithModifier *InterfaceWithModifierLiteral  `parser:"'=' (@@"`
		Value                 ValueBraceOrSpaceList[Literal] `parser:"| @@)"`
	}
	AnchorRule struct {
		Name          Value[Text]                   `parser:"'anchor' @@"`
		Direction     *string                       `parser:"@('in' | 'out')?"`
		OnIfSpec      *IfSpec                       `parser:"('on' @@)?"`
		AddressFamily *AddressFamily                `parser:"@@?"`
		ProtoSpec     *ProtoSpec                    `parser:"@@?"`
		Hosts         *Hosts                        `parser:"@@?"`
		FilterOptions *ValueOrRawList[FilterOption] `parser:"@@?"`
		Body          []*Line                       `parser:"'{' EOL (@@ EOL?)* EOL? '}'"`
	}
	TableAddress struct {
		Hostname   *string          `parser:"@Hostname"`
		Self       BooleanSet       `parser:"| @('self')"`
		IfSpec     *IfSpec          `parser:"| @@"`
		Prefix     *netip.Prefix    `parser:"| @CIDR"`
		AbbrevCIDR *AbbreviatedCIDR `parser:"| @AbbrevCIDR"`
		Address    *netip.Addr      `parser:"| @Address"`
	}
	TableAddressSpec struct {
		Negate BooleanSet   `parser:"@('!')?"`
		Target TableAddress `parser:"@@"`
	}
	TableOption struct {
		Persist   BooleanSet                          `parser:"@('persist')"`
		Const     BooleanSet                          `parser:"| @('const')"`
		Counters  BooleanSet                          `parser:"| @('counters')"`
		File      *Value[Text]                        `parser:"| ('file' @@)"`
		Addresses *ValueOrBraceList[TableAddressSpec] `parser:"| @@"`
	}
	TableRule struct {
		Name       Value[Text]    `parser:"'table' '<' @@ '>'"`
		EmptyBlock BooleanSet     `parser:"( @('{' '}')"`
		Options    []*TableOption `parser:"| @@+ )"`
	}
	Line struct {
		Pos           lexer.Position `parser:""`
		Option        *Option        `parser:"@@"`
		PfRule        *PfRule        `parser:"| @@"`
		Comment       *Comment       `parser:"| @Comment"`
		AntiSpoofRule *AntiSpoofRule `parser:"| @@"`
		Include       *Include       `parser:"| @@"`
		Assignment    *Assignment    `parser:"| @@"`
		// QueueRule *QueueRule     `parser:"| @@"`
		AnchorRule *AnchorRule `parser:"| @@"`
		// LoadAnchor *LoadAnchor    `parser:"| @@"`
		TableRule *TableRule     `parser:"| @@"`
		EndPos    lexer.Position `parser:""`

		rawText string
	}
	Configuration struct {
		Line []*Line `parser:"(EOL* @@ EOL?)* EOL*"`

		source string // original input text, set after parsing
	}
)

// RawText returns the original configuration line as it appeared in the input.
func (l *Line) RawText() string {
	return l.rawText
}

// setRawText stores the original line text on this Line.
func (l *Line) setRawText(s string) {
	l.rawText = s
}

// populateRawText extracts the original text for each Line from the stored source
// using the positional information provided by participle.
func (c *Configuration) populateRawText() {
	if c == nil || c.source == "" {
		return
	}
	lines := strings.Split(c.source, "\n")
	for _, l := range c.Line {
		if l == nil {
			continue
		}
		// Pos.Line is 1-based
		startLine := l.Pos.Line
		endLine := l.EndPos.Line
		if startLine < 1 {
			continue
		}
		if endLine < startLine {
			endLine = startLine
		}
		// Clamp to available lines
		if startLine > len(lines) {
			continue
		}
		if endLine > len(lines) {
			endLine = len(lines)
		}
		raw := strings.Join(lines[startLine-1:endLine], "\n")
		l.setRawText(strings.TrimRight(raw, "\r\n"))
	}
}
