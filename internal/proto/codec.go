package proto

import "encoding/json"

// Codec marshals and unmarshals control-plane messages
type Codec interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	MediaType() string // value for Content-Type / Accept headers
}

func NewJSONCodec() Codec { return jsonCodec{} }

type jsonCodec struct{}

func (jsonCodec) Marshal(v any) ([]byte, error)      { return json.Marshal(v) }
func (jsonCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
func (jsonCodec) MediaType() string                  { return "application/json" }
