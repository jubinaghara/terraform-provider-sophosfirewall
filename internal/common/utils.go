package common

import (
	"os"
)

// CreateTempFile creates a temporary file with the given content
func CreateTempFile(content []byte) (string, error) {
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