package machost

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
    "github.com/jubinaghara/terraform-provider-sophosfirewall/internal/common"
)

// Client for IPHost operations
type Client struct {
	*common.BaseClient
}

// NewClient creates a new IPHost client
func NewClient(baseClient *common.BaseClient) *Client {
	return &Client{
		BaseClient: baseClient,
	}
}

// XML API request structures specific to MACHost
type setMACHostBlockXML struct {
	Operation string     `xml:"operation,attr"`
	MACHosts  []*MACHost `xml:"MACHost"`
}

type requestXML struct {
    XMLName xml.Name `xml:"Request"`
    Login   loginXML `xml:"Login"`
    Set     interface{} `xml:"Set,omitempty"`
}

type loginXML struct {
	Username string `xml:"Username"`
 	Password string `xml:"Password"`
 }

// CreateMACHost creates a new MAC Host
func (c *Client) CreateMACHost(macHost *MACHost) error {
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
		c.BaseClient.Username,
		c.BaseClient.Password,
		macHost.Name,
		macHost.Description,
		macHost.Type)

	// Add type-specific fields
	if macHost.Type == "MACAddress" {
		requestXML += fmt.Sprintf("\n<MACAddress>%s</MACAddress>", macHost.MACAddress)
	} else if macHost.Type == "MACLIST" {
		// For MACLIST type, add all MAC addresses
		requestXML += "\n<MACList>"
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
	tempFileName, err := common.CreateTempFile([]byte(requestXML))
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

	url := fmt.Sprintf("%s/webconsole/APIController", c.BaseClient.Endpoint)

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
func (c *Client) ReadMACHost(name string) (*MACHost, error) {
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
</Request>`, c.BaseClient.Username, c.BaseClient.Password, name)

    // Create a temporary file with the request content
    tempFileName, err := common.CreateTempFile([]byte(requestBody))
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

    url := fmt.Sprintf("%s/webconsole/APIController", c.BaseClient.Endpoint)
    
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

func (c *Client) UpdateMACHost(macHost *MACHost) error {
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
		c.BaseClient.Username,
		c.BaseClient.Password,
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
	tempFileName, err := common.CreateTempFile([]byte(requestXML))
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

	url := fmt.Sprintf("%s/webconsole/APIController", c.BaseClient.Endpoint)

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
func (c *Client) DeleteMACHost(name string) error {
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
</Request>`, c.BaseClient.Username, c.BaseClient.Password, name)

    // Create a temporary file with the request content
    tempFileName, err := common.CreateTempFile([]byte(requestBody))
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

    url := fmt.Sprintf("%s/webconsole/APIController", c.BaseClient.Endpoint)
    
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

