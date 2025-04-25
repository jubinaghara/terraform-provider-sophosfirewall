// internal/provider/client.go
package provider

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// SophosClient handles communication with the Sophos XML API
type SophosClient struct {
	endpoint string
	username string
	password string
	client   *http.Client
}

// NewSophosClient creates a new API client
func NewSophosClient(endpoint, username, password string, insecure bool) *SophosClient {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecure,
			},
		},
	}

	return &SophosClient{
		endpoint: endpoint,
		username: username,
		password: password,
		client:   httpClient,
	}
}

// IPHost represents a Sophos firewall IP host object
type IPHost struct {
	XMLName           xml.Name       `xml:"IPHost"`
	Name            string         `xml:"Name"`
	IPFamily          string         `xml:"IPFamily,omitempty"`
	HostType          string         `xml:"HostType"`
	IPAddress         string         `xml:"IPAddress,omitempty"`
	Subnet            string         `xml:"Subnet,omitempty"`
	StartIPAddress    string         `xml:"StartIPAddress,omitempty"`
	EndIPAddress      string         `xml:"EndIPAddress,omitempty"`
	ListOfIPAddresses string         `xml:"ListOfIPAddresses,omitempty"`
	HostGroupList     *HostGroupList `xml:"HostGroupList,omitempty"`
	TransactionID     string         `xml:"transactionid,attr,omitempty"` // Added TransactionID
}

// HostGroupList contains multiple host group references
type HostGroupList struct {
	HostGroups []string `xml:"HostGroup"`
}

// --- New: XML API bulk request structures --- //
type requestXML struct {
	XMLName xml.Name `xml:"Request"`
	Login   loginXML `xml:"Login"`
	Set     setBlockXML `xml:"Set"`
}

type loginXML struct {
	Username string `xml:"Username"`
	Password string `xml:"Password"`
}

type setBlockXML struct {
	Operation string    `xml:"operation,attr"`
	IPHosts   []*IPHost `xml:"IPHost"`
}

// createTempFile creates a temporary file with the given content.
func createTempFile(content []byte) (string, error) {
	tmpfile, err := os.CreateTemp("", "sophos_xml_payload")
	if err != nil {
		return "", err
	}
	defer tmpfile.Close()

	_, err = tmpfile.Write(content)
	if err != nil {
		return "", err
	}
	return tmpfile.Name(), nil
}

// --- New: Bulk IPHost creation using XML API --- //
func (c *SophosClient) CreateIPHostsBulk(ipHosts []*IPHost, operation string) error {

    fmt.Printf("Creating IPHosts with operation: %s\n", operation)
    request := requestXML{
        Login: loginXML{
            Username: c.username,
            Password: c.password,
        },
        Set: setBlockXML{
            Operation: operation, // "add", "update", or "delete"
            IPHosts:   ipHosts,
        },
    }

    xmlData, err := xml.MarshalIndent(request, "", "  ")
    if err != nil {
        return fmt.Errorf("error marshaling XML API request: %v", err)
    }

    fmt.Printf("XML Request:\n%s\n", string(xmlData))
    tempFileName, err := createTempFile(xmlData)
    if err != nil {
        return fmt.Errorf("error creating temporary file: %v", err)
    }
    defer os.Remove(tempFileName)

    // Create a temporary file for the response
    responseTempFile, err := os.CreateTemp("", "sophos_response")
    if err != nil {
        return fmt.Errorf("error creating response temporary file: %v", err)
    }
    responseTempFileName := responseTempFile.Name()
    responseTempFile.Close() // Close it now so curl can write to it
    defer os.Remove(responseTempFileName)

    url := fmt.Sprintf("%s/webconsole/APIController", c.endpoint)

    // Construct the curl command using the correct syntax for the file
    cmd := exec.Command("curl",
        "-k", // Insecure (as per user request)
        url,
        "-F", fmt.Sprintf("reqxml=<%s", tempFileName), // Use < instead of @ 
        "-o", responseTempFileName, // Output response to a file
    )

    var errb bytes.Buffer
    cmd.Stderr = &errb

    err = cmd.Run()
    if err != nil {
        return fmt.Errorf("error executing curl: %v, stderr: %s", err, errb.String())
    }

    // Read the response from the file
    responseData, err := os.ReadFile(responseTempFileName)
    if err != nil {
        return fmt.Errorf("error reading response file: %v", err)
    }
    
    responseBody := string(responseData)
    fmt.Printf("API Response: %s\n", responseBody)

    // Parse the response to check for errors
    var response struct {
        XMLName   xml.Name `xml:"Response"`
        APIVersion string `xml:"APIVersion,attr"`
        Login     struct {
            Status string `xml:"status"`
        } `xml:"Login"`
        IPHost    struct {
            Status struct {
                Code    string `xml:"code,attr"`
                Message string `xml:",chardata"`
            } `xml:"Status"`
        } `xml:"IPHost"`
        Error     struct {
            Code    string `xml:"code,attr"`
            Message string `xml:",chardata"`
        } `xml:"Error"`
    }

    err = xml.Unmarshal(responseData, &response)
    if err != nil {
        return fmt.Errorf("error unmarshaling response: %v", err)
    }

    // Check login status
    if response.Login.Status != "Authentication Successful" {
        return fmt.Errorf("authentication failed: %s", response.Login.Status)
    }

    // Check for API errors
    if response.Error.Code != "" {
        return fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
    }

    // Check the status code
    if response.IPHost.Status.Code != "200" {
        return fmt.Errorf("operation failed: %s", response.IPHost.Status.Message)
    }

    return nil
}

// CreateIPHost creates a new IP Host.  This function now uses the bulk create
// to be consistent.
func (c *SophosClient) CreateIPHost(ipHost *IPHost) error {
	ipHost.TransactionID = "" // Ensure no TransactionID is set.

	return c.CreateIPHostsBulk([]*IPHost{ipHost}, "add")
}

// ReadIPHost reads an existing IP Host.
func (c *SophosClient) ReadIPHost(name string) (*IPHost, error) {
    // Format the request to match the expected structure
    requestBody := fmt.Sprintf(`<Request>
   <Login>
        <Username>%s</Username>
        <Password>%s</Password>
    </Login>
    <Get> 
        <IPHost>
            <Name>%s</Name>
        </IPHost>
    </Get>
</Request>`, c.username, c.password, name)

    // Create a temporary file with the request content
    tempFileName, err := createTempFile([]byte(requestBody))
    if err != nil {
        return nil, fmt.Errorf("error creating temporary file for read: %v", err)
    }
    defer os.Remove(tempFileName)

    // Create a temporary file for the response
    responseTempFile, err := os.CreateTemp("", "sophos_response")
    if err != nil {
        return nil, fmt.Errorf("error creating response temporary file: %v", err)
    }
    responseTempFileName := responseTempFile.Name()
    responseTempFile.Close() // Close it now so curl can write to it
    defer os.Remove(responseTempFileName)

    url := fmt.Sprintf("%s/webconsole/APIController", c.endpoint)
    
    // Execute curl command with the correct format - note the difference in how the file is passed
    cmd := exec.Command("curl",
        "-k",
        url,
        "-F", fmt.Sprintf("reqxml=<%s", tempFileName), // Note the < instead of @ for the file
        "-o", responseTempFileName, // Output response to a file
    )
    
    var outb, errb bytes.Buffer
    cmd.Stdout = &outb
    cmd.Stderr = &errb

    err = cmd.Run()
    if err != nil {
        return nil, fmt.Errorf("error executing curl for read: %v, stderr: %s", err, errb.String())
    }

    // Read the response from the file
    responseData, err := os.ReadFile(responseTempFileName)
    if err != nil {
        return nil, fmt.Errorf("error reading response file: %v", err)
    }
    
    responseBody := string(responseData)
    fmt.Printf("API Response: %s\n", responseBody)
    
    // Check for empty response
    if len(responseBody) == 0 {
        return nil, fmt.Errorf("received empty response from Sophos API")
    }

    // Parse the response XML
    var response struct {
        XMLName   xml.Name `xml:"Response"`
        APIVersion string `xml:"APIVersion,attr"`
        Login     struct {
            Status string `xml:"status"`
        } `xml:"Login"`
        IPHost    *IPHost `xml:"IPHost"`
        Status    struct {
            Code    string `xml:"code,attr"`
            Message string `xml:",chardata"`
        } `xml:"Status"`
        Error     struct {
            Code    string `xml:"code,attr"`
            Message string `xml:",chardata"`
        } `xml:"Error"`
    }

    err = xml.Unmarshal(responseData, &response)
    if err != nil {
        return nil, fmt.Errorf("error unmarshaling read XML API response: %v, body: %s", err, responseBody)
    }

    // Check login status
    if response.Login.Status != "Authentication Successful" {
        return nil, fmt.Errorf("authentication failed: %s", response.Login.Status)
    }

    // Check for API errors
    if response.Error.Code != "" {
        return nil, fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
    }

    // Return the IPHost if found
    if response.IPHost != nil {
        return response.IPHost, nil
    }

    // If we get here, the IPHost wasn't found
    return nil, nil
}

// UpdateIPHost updates an existing IP Host.
func (c *SophosClient) UpdateIPHost(ipHost *IPHost) error {
	ipHost.TransactionID = ""
	return c.CreateIPHostsBulk([]*IPHost{ipHost}, "update")
}

// DeleteIPHost deletes an IP Host.
func (c *SophosClient) DeleteIPHost(name string) error {
	// Use a simplified IPHost object with only the Name for deletion.
	deleteHost := &IPHost{
		Name: name,
	}
	return c.CreateIPHostsBulk([]*IPHost{deleteHost}, "delete")
}



// Add these methods to the internal/provider/client.go file

// CreateFirewallRule creates a new firewall rule
func (c *SophosClient) CreateFirewallRule(rule *FirewallRule) error {
	return c.createFirewallRulesBulk([]*FirewallRule{rule}, "add")
}

// ReadFirewallRule reads an existing firewall rule
func (c *SophosClient) ReadFirewallRule(name string) (*FirewallRule, error) {
	// Format the request
	requestBody := fmt.Sprintf(`<Request>
   <Login>
        <Username>%s</Username>
        <Password>%s</Password>
    </Login>
    <Get> 
        <FirewallRule>
            <Name>%s</Name>
        </FirewallRule>
    </Get>
</Request>`, c.username, c.password, name)

	// Create a temporary file with the request content
	tempFileName, err := createTempFile([]byte(requestBody))
	if err != nil {
		return nil, fmt.Errorf("error creating temporary file for read: %v", err)
	}
	defer os.Remove(tempFileName)

	// Create a temporary file for the response
	responseTempFile, err := os.CreateTemp("", "sophos_response")
	if err != nil {
		return nil, fmt.Errorf("error creating response temporary file: %v", err)
	}
	responseTempFileName := responseTempFile.Name()
	responseTempFile.Close() // Close it now so curl can write to it
	defer os.Remove(responseTempFileName)

	url := fmt.Sprintf("%s/webconsole/APIController", c.endpoint)
	
	// Execute curl command
	cmd := exec.Command("curl",
		"-k",
		url,
		"-F", fmt.Sprintf("reqxml=<%s", tempFileName),
		"-o", responseTempFileName,
	)
	
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error executing curl for read: %v, stderr: %s", err, errb.String())
	}

	// Read the response from the file
	responseData, err := os.ReadFile(responseTempFileName)
	if err != nil {
		return nil, fmt.Errorf("error reading response file: %v", err)
	}
	
	responseBody := string(responseData)
	fmt.Printf("API Response: %s\n", responseBody)
	
	// Check for empty response
	if len(responseBody) == 0 {
		return nil, fmt.Errorf("received empty response from Sophos API")
	}

	// Parse the response XML
	var response struct {
		XMLName      xml.Name `xml:"Response"`
		APIVersion   string   `xml:"APIVersion,attr"`
		Login        struct {
			Status string `xml:"status"`
		} `xml:"Login"`
		FirewallRule *FirewallRule `xml:"FirewallRule"`
		Status       struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Status"`
		Error        struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Error"`
	}

	err = xml.Unmarshal(responseData, &response)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling read XML API response: %v, body: %s", err, responseBody)
	}

	// Check login status
	if response.Login.Status != "Authentication Successful" {
		return nil, fmt.Errorf("authentication failed: %s", response.Login.Status)
	}

	// Check for API errors
	if response.Error.Code != "" {
		return nil, fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
	}

	// Return the FirewallRule if found
	if response.FirewallRule != nil {
		return response.FirewallRule, nil
	}

	// If we get here, the FirewallRule wasn't found
	return nil, nil
}

// UpdateFirewallRule updates an existing firewall rule
func (c *SophosClient) UpdateFirewallRule(rule *FirewallRule) error {
	rule.TransactionID = ""
	return c.createFirewallRulesBulk([]*FirewallRule{rule}, "update")
}

// DeleteFirewallRule deletes a firewall rule
func (c *SophosClient) DeleteFirewallRule(name string) error {
	// Use a simplified FirewallRule object with only the Name for deletion
	deleteRule := &FirewallRule{
		Name: name,
	}
	return c.createFirewallRulesBulk([]*FirewallRule{deleteRule}, "delete")
}

// Bulk operation for firewall rules
func (c *SophosClient) createFirewallRulesBulk(rules []*FirewallRule, operation string) error {
	fmt.Printf("Creating firewall rules with operation: %s\n", operation)
	
	request := firewallRuleRequestXML{
		Login: loginXML{
			Username: c.username,
			Password: c.password,
		},
		Set: firewallRuleSetXML{
			Operation:     operation, // "add", "update", or "delete"
			FirewallRules: rules,
		},
	}

	xmlData, err := xml.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling XML API request: %v", err)
	}

	fmt.Printf("XML Request:\n%s\n", string(xmlData))
	tempFileName, err := createTempFile(xmlData)
	if err != nil {
		return fmt.Errorf("error creating temporary file: %v", err)
	}
	defer os.Remove(tempFileName)

	// Create a temporary file for the response
	responseTempFile, err := os.CreateTemp("", "sophos_response")
	if err != nil {
		return fmt.Errorf("error creating response temporary file: %v", err)
	}
	responseTempFileName := responseTempFile.Name()
	responseTempFile.Close() // Close it now so curl can write to it
	defer os.Remove(responseTempFileName)

	url := fmt.Sprintf("%s/webconsole/APIController", c.endpoint)

	// Execute curl command
	cmd := exec.Command("curl",
		"-k", // Insecure (as per user request)
		url,
		"-F", fmt.Sprintf("reqxml=<%s", tempFileName),
		"-o", responseTempFileName,
	)

	var errb bytes.Buffer
	cmd.Stderr = &errb

	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("error executing curl: %v, stderr: %s", err, errb.String())
	}

	// Read the response from the file
	responseData, err := os.ReadFile(responseTempFileName)
	if err != nil {
		return fmt.Errorf("error reading response file: %v", err)
	}
	
	responseBody := string(responseData)
	fmt.Printf("API Response: %s\n", responseBody)

	// Parse the response to check for errors
	var response struct {
		XMLName   xml.Name `xml:"Response"`
		APIVersion string `xml:"APIVersion,attr"`
		Login     struct {
			Status string `xml:"status"`
		} `xml:"Login"`
		FirewallRule struct {
			Status struct {
				Code    string `xml:"code,attr"`
				Message string `xml:",chardata"`
			} `xml:"Status"`
		} `xml:"FirewallRule"`
		Error     struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Error"`
	}

	err = xml.Unmarshal(responseData, &response)
	if err != nil {
		return fmt.Errorf("error unmarshaling response: %v", err)
	}

	// Check login status
	if response.Login.Status != "Authentication Successful" {
		return fmt.Errorf("authentication failed: %s", response.Login.Status)
	}

	// Check for API errors
	if response.Error.Code != "" {
		return fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
	}

	// Check the status code
	if response.FirewallRule.Status.Code != "200" {
		return fmt.Errorf("operation failed: %s", response.FirewallRule.Status.Message)
	}

	return nil
}