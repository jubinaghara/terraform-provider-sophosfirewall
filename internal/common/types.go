package common

import (
	"crypto/tls"
	"net/http"
)

// BaseClient provides common client functionality for all service clients
type BaseClient struct {
	Endpoint string
	Username string
	Password string
	Client   *http.Client
}

// NewBaseClient creates a new base client
func NewBaseClient(endpoint, username, password string, insecure bool) *BaseClient {
	return &BaseClient{
		Endpoint: endpoint,
		Username: username,
		Password: password,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: insecure,
				},
			},
		},
	}
}

// XML API request structures - common to all clients
type RequestXML struct {
	XMLName interface{} `xml:"Request"`
	Login   LoginXML    `xml:"Login"`
	Set     interface{} `xml:"Set,omitempty"`
	Get     interface{} `xml:"Get,omitempty"`
	Remove  interface{} `xml:"Remove,omitempty"`
}

type LoginXML struct {
	Username string `xml:"Username"`
	Password string `xml:"Password"`
}