package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrMissingMessageType = errors.New("protocol: missing envelope message type")
	ErrEmptyPayload       = errors.New("protocol: empty envelope payload")
	ErrNilDestination     = errors.New("protocol: decode destination must be non-nil")
)

// Envelope is the top-level JSON frame exchanged over /api/v1/agent/ws.
type Envelope struct {
	Type    string          `json:"type"`
	ReqID   string          `json:"req_id"`
	Payload json.RawMessage `json:"payload"`
}

// NewEnvelope builds an Envelope by JSON-marshaling payload.
// If payload is nil, Payload defaults to `{}`.
func NewEnvelope(msgType, reqID string, payload any) (Envelope, error) {
	if msgType == "" {
		return Envelope{}, ErrMissingMessageType
	}
	var raw json.RawMessage
	if payload == nil {
		raw = json.RawMessage("{}")
	} else {
		b, err := json.Marshal(payload)
		if err != nil {
			return Envelope{}, fmt.Errorf("protocol: marshal payload for %s: %w", msgType, err)
		}
		raw = b
	}
	return Envelope{
		Type:    msgType,
		ReqID:   reqID,
		Payload: raw,
	}, nil
}

// MarshalEnvelope constructs and JSON-encodes an Envelope in one step.
func MarshalEnvelope(msgType, reqID string, payload any) ([]byte, error) {
	env, err := NewEnvelope(msgType, reqID, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

// ParseEnvelope decodes raw JSON bytes into an Envelope and validates Type.
func ParseEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return Envelope{}, fmt.Errorf("protocol: unmarshal envelope: %w", err)
	}
	if env.Type == "" {
		return Envelope{}, ErrMissingMessageType
	}
	return env, nil
}

// DecodePayload unmarshals Envelope.Payload into dst.
func (e Envelope) DecodePayload(dst any) error {
	if dst == nil {
		return ErrNilDestination
	}
	trimmed := bytes.TrimSpace(e.Payload)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ErrEmptyPayload
	}
	if err := json.Unmarshal(trimmed, dst); err != nil {
		return fmt.Errorf("protocol: decode payload for %s: %w", e.Type, err)
	}
	return nil
}
