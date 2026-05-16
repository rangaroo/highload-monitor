package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rangaroo/highload-monitor/internal/proto"
)

// Server exposes the PF control plane over HTTP
type Server struct {
	codec      proto.Codec
	engine     *FilterEngine
	forwarders []*Forwarder
	dumpAddr   string // host:port of the TCP dump listener
}

func NewServer(codec proto.Codec, engine *FilterEngine, fwds []*Forwarder, dumpAddr string) *Server {
	return &Server{codec: codec, engine: engine, forwarders: fwds, dumpAddr: dumpAddr}
}

// Handler returns an http.Handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(proto.PathHealth, s.handleHealth)
	mux.HandleFunc(proto.PathStats, s.handleStats)
	mux.HandleFunc(proto.PathFilters, s.handleFilters)
	mux.HandleFunc(proto.PathFilters+"/", s.handleFilters) // DELETE /v1/filters/{id}
	mux.HandleFunc(proto.PathDumpEndpoint, s.handleDumpEndpoint)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.writeJSON(w, proto.HealthResponse{Status: "ok"})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var rx, tx uint64
	var drops, freeze uint64
	for _, f := range s.forwarders {
		fs := f.Stats()
		rx += fs.RXPackets
		tx += fs.TXPackets
		ks, err := f.RXStats()
		if err != nil {
			http.Error(w, fmt.Sprintf("stats: %v", err), http.StatusInternalServerError)
			return
		}
		drops += uint64(ks.Drops)
		freeze += uint64(ks.FreezeQCount)
	}

	s.writeJSON(w, proto.StatsResponse{
		RXPackets:    rx,
		RXDrops:      drops,
		TXPackets:    tx,
		FreezeQCount: freeze,
	})
}

func (s *Server) handleFilters(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.writeJSON(w, proto.FilterListResponse{Filters: s.engine.List()})

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		var req proto.AddFilterRequest
		if err := s.codec.Unmarshal(body, &req); err != nil {
			http.Error(w, fmt.Sprintf("decode: %v", err), http.StatusBadRequest)
			return
		}

		id, err := s.engine.Add(req.Filter)
		if err != nil {
			http.Error(w, fmt.Sprintf("add filter: %v", err), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		s.writeJSON(w, proto.AddFilterResponse{ID: id})

	case http.MethodDelete:
		// DELETE /v1/filters/{id}
		id := strings.TrimPrefix(r.URL.Path, proto.PathFilters+"/")
		if id == "" {
			http.Error(w, "missing filter id", http.StatusBadRequest)
			return
		}

		s.engine.Remove(id)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDumpEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.writeJSON(w, proto.DumpEndpointResponse{Addr: s.dumpAddr})
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	data, err := s.codec.Marshal(v)
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", s.codec.MediaType())
	w.Write(data) //nolint:errcheck
}
