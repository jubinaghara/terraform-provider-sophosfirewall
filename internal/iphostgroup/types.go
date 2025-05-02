package iphostgroup

// IPHost represents the firewall IP host model
type IPHostGroup struct {
	Name             string `xml:"Name"`
	Description      string `xml:"Description"`
	IPFamily         string `xml:"IPFamily"`
	HostList    	*HostList `xml:"HostList"`
	TransactionID    string `xml:"transactionid,attr"`
}

// HostGroupList represents the host group list in the XML response
type HostList struct {
	Hosts []string `xml:"Host"`
}

