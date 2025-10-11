package host

type config struct {
	Records map[string]string `json:"records"` // domain -> comma separated IP list
	Files   []string          `json:"files"`
}
