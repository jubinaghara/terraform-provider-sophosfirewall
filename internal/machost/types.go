package machost

type MACHost struct {
	Name                string   `xml:"Name"`
	Description         string   `xml:"Description"`
	Type                string   `xml:"Type"`
	MACAddress          string   `xml:"MACAddress,omitempty"`
	ListOfMACAddresses  []string `xml:"-"` // This will be populated from the MACList structure
	TransactionID       string   `xml:"transactionid,attr"`
}