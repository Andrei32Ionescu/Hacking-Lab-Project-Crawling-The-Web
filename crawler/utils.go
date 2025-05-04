package crawler

import (
	"encoding/json"
	"os"
)

// SaveToJSON saves quotes to a JSON file
func SaveToJSON(quotes []Quote, filepath string) error {
	// Create the file
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create an encoder and encode the quotes
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(quotes)
}