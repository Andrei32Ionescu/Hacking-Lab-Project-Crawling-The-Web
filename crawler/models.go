package crawler

// Quote represents a quote with its author and tags
type Quote struct {
	Text   string   `json:"text"`
	Author string   `json:"author"`
	Tags   []string `json:"tags"`
}
