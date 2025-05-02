package iphost

// IPHost represents the firewall IP host model
type IPHost struct {
	Name             string `xml:"Name"`
	Description      string `xml:"Description"`
	IPFamily         string `xml:"IPFamily"`
	HostType         string `xml:"HostType"`
	IPAddress        string `xml:"IPAddress"`
	Subnet           string `xml:"Subnet"`
	StartIPAddress   string `xml:"StartIPAddress"`
	EndIPAddress     string `xml:"EndIPAddress"`
	TransactionID    string `xml:"transactionid,attr"`
	ListOfIPAddresses string `xml:"ListOfIPAddresses"`
	HostGroupList    *HostGroupList `xml:"HostGroupList"`
}

// HostGroupList represents the host group list in the XML response
type HostGroupList struct {
	HostGroups []string `xml:"HostGroup"`
}