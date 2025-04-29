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
	Name              string         `xml:"Name"`
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

// MACHost represents a Sophos firewall MAC host object
type MACHost struct {
	Name                string   `xml:"Name"`
	Description         string   `xml:"Description"`
	Type                string   `xml:"Type"`
	MACAddress          string   `xml:"MACAddress,omitempty"`
	ListOfMACAddresses  []string `xml:"-"` // This will be populated from the MACList structure
	TransactionID       string   `xml:"transactionid,attr"`
}

// HostGroupList contains multiple host group references
type HostGroupList struct {
	HostGroups []string `xml:"HostGroup"`
}

// --- XML API request structures for IPHost --- //
type requestXML struct {
	XMLName xml.Name `xml:"Request"`
	Login   loginXML `xml:"Login"`
	Set     interface{} `xml:"Set,omitempty"`
}

type loginXML struct {
	Username string `xml:"Username"`
	Password string `xml:"Password"`
}

type setIPHostBlockXML struct {
	Operation string    `xml:"operation,attr"`
	IPHosts   []*IPHost `xml:"IPHost"`
}

// --- XML API request structures for MACHost --- //
type setMACHostBlockXML struct {
	Operation string     `xml:"operation,attr"`
	MACHosts  []*MACHost `xml:"MACHost"`
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

// --- Bulk IPHost creation using XML API --- //
func (c *SophosClient) CreateIPHostsBulk(ipHosts []*IPHost, operation string) error {
	fmt.Printf("Creating IPHosts with operation: %s\n", operation)
	request := requestXML{
		Login: loginXML{
			Username: c.username,
			Password: c.password,
		},
		Set: setIPHostBlockXML{
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
		XMLName    xml.Name `xml:"Response"`
		APIVersion string   `xml:"APIVersion,attr"`
		Login      struct {
			Status string `xml:"status"`
		} `xml:"Login"`
		IPHost     struct {
			Status struct {
				Code    string `xml:"code,attr"`
				Message string `xml:",chardata"`
			} `xml:"Status"`
		} `xml:"IPHost"`
		Error      struct {
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

// CreateIPHost creates a new IP Host. This function now uses the bulk create to be consistent.
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
    // For update, we need to use <Set operation="update">
    request := requestXML{
        Login: loginXML{
            Username: c.username,
            Password: c.password,
        },
        Set: setIPHostBlockXML{
            Operation: "update",
            IPHosts:   []*IPHost{ipHost},
        },
    }

    // Set empty transaction ID as per requirement
    ipHost.TransactionID = ""

    xmlData, err := xml.MarshalIndent(request, "", "  ")
    if err != nil {
        return fmt.Errorf("error marshaling XML API request for update: %v", err)
    }

    fmt.Printf("XML Update Request:\n%s\n", string(xmlData))
    tempFileName, err := createTempFile(xmlData)
    if err != nil {
        return fmt.Errorf("error creating temporary file for update: %v", err)
    }
    defer os.Remove(tempFileName)

    // Create a temporary file for the response
    responseTempFile, err := os.CreateTemp("", "sophos_response")
    if err != nil {
        return fmt.Errorf("error creating response temporary file for update: %v", err)
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
        return fmt.Errorf("error executing curl for update: %v, stderr: %s", err, errb.String())
    }

    // Read the response from the file
    responseData, err := os.ReadFile(responseTempFileName)
    if err != nil {
        return fmt.Errorf("error reading response file for update: %v", err)
    }
    
    responseBody := string(responseData)
    fmt.Printf("API Update Response: %s\n", responseBody)

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
        return fmt.Errorf("error unmarshaling update response: %v", err)
    }

    // Check login status
    if response.Login.Status != "Authentication Successful" {
        return fmt.Errorf("authentication failed for update: %s", response.Login.Status)
    }

    // Check for API errors
    if response.Error.Code != "" {
        return fmt.Errorf("Sophos API error during update: %s - %s", response.Error.Code, response.Error.Message)
    }

    return nil
}

// DeleteIPHost deletes an IP Host.
func (c *SophosClient) DeleteIPHost(name string) error {
    // For deletion, we need to use the <Remove> tag instead of <Set>
    // Format the request to match the expected structure
    requestBody := fmt.Sprintf(`<Request>
   <Login>
        <Username>%s</Username>
        <Password>%s</Password>
    </Login>
    <Remove>
        <IPHost>
            <Name>%s</Name>
        </IPHost>
    </Remove>
</Request>`, c.username, c.password, name)

    // Create a temporary file with the request content
    tempFileName, err := createTempFile([]byte(requestBody))
    if err != nil {
        return fmt.Errorf("error creating temporary file for delete: %v", err)
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
    
    // Execute curl command with the correct format
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
        return fmt.Errorf("error executing curl for delete: %v, stderr: %s", err, errb.String())
    }

    // Read the response from the file
    responseData, err := os.ReadFile(responseTempFileName)
    if err != nil {
        return fmt.Errorf("error reading response file: %v", err)
    }
    
    responseBody := string(responseData)
    fmt.Printf("API Response for delete: %s\n", responseBody)
    
    // Check for empty response
    if len(responseBody) == 0 {
        return fmt.Errorf("received empty response from Sophos API")
    }

    // Parse the response XML to check for errors
    var response struct {
        XMLName   xml.Name `xml:"Response"`
        APIVersion string `xml:"APIVersion,attr"`
        Login     struct {
            Status string `xml:"status"`
        } `xml:"Login"`
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
        return fmt.Errorf("error unmarshaling delete response: %v, body: %s", err, responseBody)
    }

    // Check login status
    if response.Login.Status != "Authentication Successful" {
        return fmt.Errorf("authentication failed: %s", response.Login.Status)
    }

    // Check for API errors
    if response.Error.Code != "" {
        return fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
    }

    return nil
}

//============================================================//
//                          MAC HOST
//=============================================================//

// --- Bulk MAC Host creation using XML API --- //
// CreateMACHost creates a new MAC Host
func (c *SophosClient) CreateMACHost(macHost *MACHost) error {
	// Start building the XML request
	requestXML := fmt.Sprintf(`<Request>
    <Login>
        <Username>%s</Username>
        <Password>%s</Password>
    </Login>
    <Set operation="add">
        <MACHost>
            <Name>%s</Name>
            <Description>%s</Description>
            <Type>%s</Type>`,
		c.username,
		c.password,
		macHost.Name,
		macHost.Description,
		macHost.Type)

	// Add type-specific fields
	if macHost.Type == "MACAddress" {
		requestXML += fmt.Sprintf("\n<MACAddress>%s</MACAddress>", macHost.MACAddress)
	} else if macHost.Type == "MACLIST" {
		// For MACLIST type, add all MAC addresses
		requestXML += "\n            <MACList>"
		for _, mac := range macHost.ListOfMACAddresses {
			requestXML += fmt.Sprintf("\n<MACAddress>%s</MACAddress>", mac)
		}
		requestXML += "\n</MACList>"
	}

	// Close the XML request
	requestXML += `
        </MACHost>
        </Set>
    </Request>`

	// Create a temporary file with the request content
	tempFileName, err := createTempFile([]byte(requestXML))
	if err != nil {
		return fmt.Errorf("error creating temporary file for create: %v", err)
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
		return fmt.Errorf("error executing curl for create: %v, stderr: %s", err, errb.String())
	}

	// Read the response from the file
	responseData, err := os.ReadFile(responseTempFileName)
	if err != nil {
		return fmt.Errorf("error reading response file: %v", err)
	}

	responseBody := string(responseData)
	fmt.Printf("API Response: %s\n", responseBody)

	// Check for empty response
	if len(responseBody) == 0 {
		return fmt.Errorf("received empty response from Sophos API")
	}

	// Parse the response XML
	var response struct {
		XMLName xml.Name `xml:"Response"`
		Login   struct {
			Status string `xml:"status"`
		} `xml:"Login"`
		Status struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Status"`
		Error struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Error"`
	}

	err = xml.Unmarshal(responseData, &response)
	if err != nil {
		return fmt.Errorf("error unmarshaling create XML API response: %v, body: %s", err, responseBody)
	}

	// Check login status
	if response.Login.Status != "Authentication Successful" {
		return fmt.Errorf("authentication failed: %s", response.Login.Status)
	}

	// Check for API errors
	if response.Error.Code != "" {
		return fmt.Errorf("operation failed: %s", response.Error.Message)
	}

	// Success if no errors
	return nil
}


// ReadMACHost reads an existing MAC Host.
func (c *SophosClient) ReadMACHost(name string) (*MACHost, error) {
    // Format the request to match the expected structure
    requestBody := fmt.Sprintf(`<Request>
   <Login>
        <Username>%s</Username>
        <Password>%s</Password>
    </Login>
    <Get> 
        <MACHost>
            <Name>%s</Name>
        </MACHost>
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
    
    // Execute curl command with the correct format
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
        XMLName   xml.Name `xml:"Response"`
        APIVersion string `xml:"APIVersion,attr"`
        Login     struct {
            Status string `xml:"status"`
        } `xml:"Login"`
        MACHosts  []struct {
            Name        string   `xml:"Name"`
            Description string   `xml:"Description"`
            Type        string   `xml:"Type"`
            MACAddress  string   `xml:"MACAddress"`
            MACList     struct {
                MACAddresses []string `xml:"MACAddress"`
            } `xml:"MACList"`
            TransactionID string `xml:"transactionid,attr"`
        } `xml:"MACHost"`
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

    // Find the MAC Host with the matching name
    for _, host := range response.MACHosts {
        if host.Name == name {
            macHost := &MACHost{
                Name:          host.Name,
                Description:   host.Description,
                Type:          host.Type,
                TransactionID: host.TransactionID,
            }
            
            if host.Type == "MACAddress" {
                macHost.MACAddress = host.MACAddress
            } else if host.Type == "MACLIST" {
                // Extract the MAC addresses from the MACList structure
                macHost.ListOfMACAddresses = host.MACList.MACAddresses
            }
            
            return macHost, nil
        }
    }

    // If we get here, the MACHost wasn't found
    return nil, nil
}

// UpdateMACHost updates an existing MAC Host.
func (c *SophosClient) UpdateMACHost(macHost *MACHost) error {
	// Start building the XML request
	requestXML := fmt.Sprintf(`<Request>
    <Login>
        <Username>%s</Username>
        <Password>%s</Password>
    </Login>
    <Set operation="update">
        <MACHost>
            <n>%s</n>
            <Description>%s</Description>
            <Type>%s</Type>`,
		c.username,
		c.password,
		macHost.Name,
		macHost.Description,
		macHost.Type)

	// Add type-specific fields
	if macHost.Type == "MACAddress" {
		requestXML += fmt.Sprintf("\n            <MACAddress>%s</MACAddress>", macHost.MACAddress)
	} else if macHost.Type == "MACLIST" {
		// For MACLIST type, add all MAC addresses
		requestXML += "\n            <MACList>"
		for _, mac := range macHost.ListOfMACAddresses {
			requestXML += fmt.Sprintf("\n                <MACAddress>%s</MACAddress>", mac)
		}
		requestXML += "\n            </MACList>"
	}

	// Close the XML request
	requestXML += `
        </MACHost>
    </Set>
</Request>`

	// Create a temporary file with the request content
	tempFileName, err := createTempFile([]byte(requestXML))
	if err != nil {
		return fmt.Errorf("error creating temporary file for update: %v", err)
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
		return fmt.Errorf("error executing curl for update: %v, stderr: %s", err, errb.String())
	}

	// Read the response from the file
	responseData, err := os.ReadFile(responseTempFileName)
	if err != nil {
		return fmt.Errorf("error reading response file: %v", err)
	}

	responseBody := string(responseData)
	fmt.Printf("API Response: %s\n", responseBody)

	// Check for empty response
	if len(responseBody) == 0 {
		return fmt.Errorf("received empty response from Sophos API")
	}

	// Parse the response XML
	var response struct {
		XMLName xml.Name `xml:"Response"`
		Login   struct {
			Status string `xml:"status"`
		} `xml:"Login"`
		Status struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Status"`
		Error struct {
			Code    string `xml:"code,attr"`
			Message string `xml:",chardata"`
		} `xml:"Error"`
	}

	err = xml.Unmarshal(responseData, &response)
	if err != nil {
		return fmt.Errorf("error unmarshaling update XML API response: %v, body: %s", err, responseBody)
	}

	// Check login status
	if response.Login.Status != "Authentication Successful" {
		return fmt.Errorf("authentication failed: %s", response.Login.Status)
	}

	// Check for API errors
	if response.Error.Code != "" {
		return fmt.Errorf("operation failed: %s", response.Error.Message)
	}

	// Success if no errors
	return nil
}

// DeleteIPHost deletes an MAC Host.
func (c *SophosClient) DeleteMACHost(name string) error {
    // For deletion, we need to use the <Remove> tag instead of <Set>
    // Format the request to match the expected structure
    requestBody := fmt.Sprintf(`<Request>
   <Login>
        <Username>%s</Username>
        <Password>%s</Password>
    </Login>
    <Remove>
        <MACHost>
            <Name>%s</Name>
        </MACHost>
    </Remove>
</Request>`, c.username, c.password, name)

    // Create a temporary file with the request content
    tempFileName, err := createTempFile([]byte(requestBody))
    if err != nil {
        return fmt.Errorf("error creating temporary file for delete: %v", err)
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
    
    // Execute curl command with the correct format
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
        return fmt.Errorf("error executing curl for delete: %v, stderr: %s", err, errb.String())
    }

    // Read the response from the file
    responseData, err := os.ReadFile(responseTempFileName)
    if err != nil {
        return fmt.Errorf("error reading response file: %v", err)
    }
    
    responseBody := string(responseData)
    fmt.Printf("API Response for delete: %s\n", responseBody)
    
    // Check for empty response
    if len(responseBody) == 0 {
        return fmt.Errorf("received empty response from Sophos API")
    }

    // Parse the response XML to check for errors
    var response struct {
        XMLName   xml.Name `xml:"Response"`
        APIVersion string `xml:"APIVersion,attr"`
        Login     struct {
            Status string `xml:"status"`
        } `xml:"Login"`
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
        return fmt.Errorf("error unmarshaling delete response: %v, body: %s", err, responseBody)
    }

    // Check login status
    if response.Login.Status != "Authentication Successful" {
        return fmt.Errorf("authentication failed: %s", response.Login.Status)
    }

    // Check for API errors
    if response.Error.Code != "" {
        return fmt.Errorf("Sophos API error: %s - %s", response.Error.Code, response.Error.Message)
    }

    return nil
}



//================================================================//
// 						Firewall Rule 							  //
//================================================================//

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