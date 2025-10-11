package forward

type config struct {
	ServerList []string `json:"server_list"`
	Parallel   int      `json:"parallel"`
}
