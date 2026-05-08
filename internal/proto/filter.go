package proto

// FilterSpec describes which packets PF should tap and forward to the dump stream
type FilterSpec struct {
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  uint16 `json:"src_port,omitempty"` // 0 = any
	DstPort  uint16 `json:"dst_port,omitempty"` // 0 = any
	Protocol string `json:"protocol,omitempty"` // tcp/udp, "" = any
}
