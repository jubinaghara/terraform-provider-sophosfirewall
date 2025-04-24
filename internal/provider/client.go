// internal/provider/client.go
package provider

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
)

// SophosClient handles communication with the Sophos XML API
type SophosClient struct {
	endpoint string
	username string
	password string
	client   *http.Client
}

// NewSophosClient creates a new API client
func NewSophosClient(endpoint, username, password string) *SophosClient {
	return &SophosClient{
		endpoint: endpoint,
		username: username,
		password: password,
		client:   &http.Client{},
	}
}

// IPHost represents a Sophos firewall IP host object
type IPHost struct {
	XMLName        xml.Name  `xml:"IPHost"`
	Name           string    `xml:"Name"`
	IPFamily       string    `xml:"IPFamily,omitempty"`
	HostType       string    `xml:"HostType"`
	IPAddress      string    `xml:"IPAddress,omitempty"`
	Subnet         string    `xml:"Subnet,omitempty"`
	StartIPAddress string    `xml:"StartIPAddress,omitempty"`
	EndIPAddress   string    `xml:"EndIPAddress,omitempty"`
	ListOfIPAddresses string `xml:"ListOfIPAddresses,omitempty"`
	HostGroupList  *HostGroupList `xml:"HostGroupList,omitempty"`
}

// HostGroupList contains multiple host group references
type HostGroupList struct {
	HostGroups []string `xml:"HostGroup"`
}

// CreateIPHost creates a new IP host in the Sophos firewall
func (c *SophosClient) CreateIPHost(ipHost *IPHost) error {
	xmlData, err := xml.MarshalIndent(ipHost, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling IP host: %v", err)
	}

	url := fmt.Sprintf("%s/api/objects/iphost", c.endpoint)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(xmlData))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/xml")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// ReadIPHost retrieves an IP host from the Sophos firewall
func (c *SophosClient) ReadIPHost(name string) (*IPHost, error) {
	url := fmt.Sprintf("%s/api/objects/iphost/%s", c.endpoint, name)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Resource not found
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	var ipHost IPHost
	if err := xml.NewDecoder(resp.Body).Decode(&ipHost); err != nil {
		return nil, fmt.Errorf("error decoding response: %v", err)
	}

	return &ipHost, nil
}

// UpdateIPHost updates an existing IP host
func (c *SophosClient) UpdateIPHost(ipHost *IPHost) error {
	xmlData, err := xml.MarshalIndent(ipHost, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling IP host: %v", err)
	}

	url := fmt.Sprintf("%s/api/objects/iphost/%s", c.endpoint, ipHost.Name)
	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(xmlData))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/xml")

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// DeleteIPHost deletes an IP host
func (c *SophosClient) DeleteIPHost(name string) error {
	url := fmt.Sprintf("%s/api/objects/iphost/%s", c.endpoint, name)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}