package firewallrule

import "encoding/xml"

// FirewallRule represents a Sophos firewall rule with all available fields
type FirewallRule struct {
	XMLName             xml.Name        `xml:"FirewallRule"`
	Name                string          `xml:"Name"`
	Description         string          `xml:"Description"`
	IPFamily            string          `xml:"IPFamily"`
	Status              string          `xml:"Status"`
	Position            string          `xml:"Position"`
	PolicyType          string          `xml:"PolicyType"`
	After               *RulePosition   `xml:"After,omitempty"`
	Before              *RulePosition   `xml:"Before,omitempty"`
	NetworkPolicy       *NetworkPolicy  `xml:"NetworkPolicy,omitempty"`
	TransactionID       string          `xml:"transactionid,attr,omitempty"`
}

// RulePosition specifies the position relative to another rule
type RulePosition struct {
	Name string `xml:"Name"`
}

// NetworkPolicy contains network policy settings with all available fields
type NetworkPolicy struct {
	Action                       string            `xml:"Action"`
	LogTraffic                   string            `xml:"LogTraffic"`
	SkipLocalDestined            string            `xml:"SkipLocalDestined"`
	Schedule                     string            `xml:"Schedule"`
	SourceZones                  *ZoneList         `xml:"SourceZones"`
	DestinationZones             *ZoneList         `xml:"DestinationZones"`
	SourceNetworks               *NetworkList      `xml:"SourceNetworks,omitempty"`
	DestinationNetworks          *NetworkList      `xml:"DestinationNetworks,omitempty"`
	DSCPMarking                  string            `xml:"DSCPMarking,omitempty"`
	WebFilter                    string            `xml:"WebFilter,omitempty"`
	WebCategoryBaseQoSPolicy     string            `xml:"WebCategoryBaseQoSPolicy,omitempty"`
	BlockQuickQuic               string            `xml:"BlockQuickQuic,omitempty"`
	ScanVirus                    string            `xml:"ScanVirus,omitempty"`
	ZeroDayProtection            string            `xml:"ZeroDayProtection,omitempty"`
	ProxyMode                    string            `xml:"ProxyMode,omitempty"`
	DecryptHTTPS                 string            `xml:"DecryptHTTPS,omitempty"`
	ApplicationControl           string            `xml:"ApplicationControl,omitempty"`
	ApplicationBaseQoSPolicy     string            `xml:"ApplicationBaseQoSPolicy,omitempty"`
	IntrusionPrevention          string            `xml:"IntrusionPrevention,omitempty"`
	TrafficShappingPolicy        string            `xml:"TrafficShappingPolicy,omitempty"`
	ScanSMTP                     string            `xml:"ScanSMTP,omitempty"`
	ScanSMTPS                    string            `xml:"ScanSMTPS,omitempty"`
	ScanIMAP                     string            `xml:"ScanIMAP,omitempty"`
	ScanIMAPS                    string            `xml:"ScanIMAPS,omitempty"`
	ScanPOP3                     string            `xml:"ScanPOP3,omitempty"`
	ScanPOP3S                    string            `xml:"ScanPOP3S,omitempty"`
	ScanFTP                      string            `xml:"ScanFTP,omitempty"`
	SourceSecurityHeartbeat      string            `xml:"SourceSecurityHeartbeat,omitempty"`
	MinimumSourceHBPermitted     string            `xml:"MinimumSourceHBPermitted,omitempty"`
	DestSecurityHeartbeat        string            `xml:"DestSecurityHeartbeat,omitempty"`
	MinimumDestinationHBPermitted string           `xml:"MinimumDestinationHBPermitted,omitempty"`
}

// ZoneList contains a list of zones
type ZoneList struct {
	Zones []string `xml:"Zone"`
}

// NetworkList contains a list of networks
type NetworkList struct {
	Networks []string `xml:"Network"`
}

