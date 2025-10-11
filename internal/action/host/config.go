package host

type Record struct {
	Domain string
	IP     string
}

type config struct {
	Records []Record `json:"records"`
}
