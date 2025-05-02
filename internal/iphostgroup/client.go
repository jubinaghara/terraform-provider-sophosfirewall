package iphostgroup

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"github.com/jubinaghara/terraform-provider-sophosfirewall/internal/common"
)

type Client struct {
	*common.BaseClient
}

type setIPHostGroupBlockXML struct {
	Operation 	   string    `xml:"operation,attr"`
	IPHostGroups   []*IPHostGroup `xml:"IPHostGroup"`
}

// NewClient creates a new IPHost client
func NewClient(baseClient *common.BaseClient) *Client {
	return &Client{
		BaseClient: baseClient,
	}
}


// CreateIPHost implements single IP host creation
func (c *Client) CreateIPHostGroup(ipHostGroup *IPHostGroup) error {
	fmt.Printf("Creating IPHost with name: %s\n", ipHostGroup.Name)
	request := common.RequestXML{
		XMLName: xml.Name{Local: "Request"},
		Login: common.LoginXML{
			Username: c.BaseClient.Username,
			Password: c.BaseClient.Password,
		},
		Set: setIPHostGroupBlockXML{
			Operation: "add",
			IPHostGroups:   []*IPHostGroup{ipHostGroup}, 
		},
	}

	xmlData, err := xml.MarshalIndent(request, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling XML API request: %v", err)
	}

	fmt.Printf("XML Request:\n%s\n", string(xmlData))
	tempFileName, err := common.CreateTempFile(xmlData)
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

	url := fmt.Sprintf("%s/webconsole/APIController", c.BaseClient.Endpoint)

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
		IPHostGroup struct {
			Status struct {
				Code    string `xml:"code,attr"`
				Message string `xml:",chardata"`
			} `xml:"Status"`
		} `xml:"IPHostGroup"`
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
	if response.IPHostGroup.Status.Code != "200" {
		return fmt.Errorf("operation failed: %s", response.IPHostGroup.Status.Message)
	}

	return nil
}

// ReadIPHost implements IP host reading
func (c *Client) ReadIPHostGroup(name string) (*IPHostGroup, error) {
	// Format the request to match the expected structure
	requestBody := fmt.Sprintf(`<Request>
	<Login>
		<Username>%s</Username>
		<Password>%s</Password>
	</Login>
		<Get> 
			<IPHostGroup>
				<Name>%s</Name>
			</IPHostGroup>
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
		IPHostGroups    []IPHostGroup `xml:"IPHostGroup"` // Changed to slice to handle multiple hosts
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
   
	// Find the IPHost with the matching name
	var targetIPHostGroup *IPHostGroup
	for i := range response.IPHostGroups {
		if response.IPHostGroups[i].Name == name {
			// Create a copy to avoid issues with slice references
			host := response.IPHostGroups[i]
			targetIPHostGroup = &host
			break
		}
	}
   
	// Return the IPHost Group if found
	if targetIPHostGroup != nil {
		// Handle HostList properly
		if targetIPHostGroup.HostList != nil && len(targetIPHostGroup.HostList.Hosts) > 0 {
			// Deduplicate host groups to prevent duplicates in state
			uniqueGroups := make(map[string]bool)
			for _, group := range targetIPHostGroup.HostList.Hosts {
				uniqueGroups[group] = true
			}
			
			// Convert back to slice
			deduplicatedGroups := make([]string, 0, len(uniqueGroups))
			for group := range uniqueGroups {
				deduplicatedGroups = append(deduplicatedGroups, group)
			}
			
			// Update the host groups list
			targetIPHostGroup.HostList.Hosts = deduplicatedGroups
		} else {
			// Initialize with empty HostGroupList
			targetIPHostGroup.HostList = &HostList{
				Hosts: []string{},
			}
		}

		return targetIPHostGroup, nil
	}
   
	// If we get here, the IPHost wasn't found
	return nil, nil
}

// UpdateIPHost implements IP host updating
func (c *Client) UpdateIPHostGroup(ipHostGroup *IPHostGroup) error {
	request := common.RequestXML{
		XMLName: xml.Name{Local: "Request"},
		Login: common.LoginXML{
			Username: c.BaseClient.Username,
			Password: c.BaseClient.Password,
		},
		Set: setIPHostGroupBlockXML{
			Operation: "update",
			IPHostGroups:   []*IPHostGroup{ipHostGroup}, 
		},
	}

    // Set empty transaction ID as per requirement
    ipHostGroup.TransactionID = ""

    xmlData, err := xml.MarshalIndent(request, "", "  ")
    if err != nil {
        return fmt.Errorf("error marshaling XML API request for update: %v", err)
    }

    fmt.Printf("XML Update Request:\n%s\n", string(xmlData))
    tempFileName, err := common.CreateTempFile(xmlData)
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

    url := fmt.Sprintf("%s/webconsole/APIController", c.BaseClient.Endpoint)

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
        IPHostGroup    struct {
            Status struct {
                Code    string `xml:"code,attr"`
                Message string `xml:",chardata"`
            } `xml:"Status"`
        } `xml:"IPHostGroup"`
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

// DeleteIPHost implements IP host deletion
func (c *Client) DeleteIPHostGroup(name string) error {
    // For deletion, we need to use the <Remove> tag instead of <Set>
    // Format the request to match the expected structure
    requestBody := fmt.Sprintf(`<Request>
   <Login>
        <Username>%s</Username>
        <Password>%s</Password>
    </Login>
    <Remove>
        <IPHostGroup>
            <Name>%s</Name>
        </IPHostGroup>
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