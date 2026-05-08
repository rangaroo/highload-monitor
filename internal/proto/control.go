package proto

// HTTP API paths for both PF and analyzer
const (
	PathHealth       = "/v1/health"
	PathStats        = "/v1/stats"
	PathFilters      = "/v1/filters"
	PathDumpEndpoint = "/v1/dump-endpoint"
)

// HealthResponse is returned by GET /v1/health
type HealthResponse struct {
	Status string `json:"status"` // "ok"
}

// StatsResponse is returned by GET /v1/stats
// Drops > 0 means the RX ring overflowed, packets were lost
type StatsResponse struct {
	RXPackets    uint64 `json:"rx_packets"`
	RXDrops      uint64 `json:"rx_drops"`
	TXPackets    uint64 `json:"tx_packets"`
	FreezeQCount uint64 `json:"freeze_q_count"`
}

// FilterID uniquely identifies a registered dump filter
type FilterID = string

// AddFilterRequest is the body of POST /v1/filters
type AddFilterRequest struct {
	Filter FilterSpec `json:"filter"`
}

// AddFilterResponse is returned by POST /v1/filters on success
type AddFilterResponse struct {
	ID FilterID `json:"id"`
}

// FilterListResponse is returned by GET /v1/filters
type FilterListResponse struct {
	Filters []FilterEntry `json:"filters"`
}

// FilterEntry pairs a filter with its assigned ID
type FilterEntry struct {
	ID     FilterID   `json:"id"`
	Filter FilterSpec `json:"filter"`
}

// DumpEndpointResponse is returned by GET /v1/dump-endpoint
// analyzer dials this address to receive the raw TCP dump stream
type DumpEndpointResponse struct {
	Addr string `json:"addr"` // host:port format
}
