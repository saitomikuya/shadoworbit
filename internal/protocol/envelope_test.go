package protocol

import (
	"errors"
	"reflect"
	"testing"
)

func TestEnvelopeRoundTripAllMessageTypes(t *testing.T) {
	hello := AgentHello{
		OS:            "linux",
		Arch:          "amd64",
		CPUCores:      4,
		TotalRAMBytes: 4294967296,
		PublicIPv4:    "203.0.113.10",
		PublicIPv6:    "2001:db8::10",
		Versions: AgentVersions{
			SingBox:     "1.11.0",
			SnellServer: "v5.0.0",
			ShadowTLS:   "v0.2.25",
		},
		ConfigRevision: 7,
	}

	metrics := AgentMetrics{
		TS:              1760000000,
		CPUPercent:      12.5,
		MemUsedBytes:    1024,
		MemTotalBytes:   4096,
		DiskUsedPercent: 33.3,
		UptimeSeconds:   86400,
		RxBPS:           12345,
		TxBPS:           67890,
		NicRxDelta:      50000,
		NicTxDelta:      75000,
		UserDeltas: []UserTrafficDelta{
			{Username: "alice", UserID: 2, UpBytes: 100, DownBytes: 200},
		},
		Health: AgentHealth{Snell: true, ShadowTLS: true, SingBox: true},
	}

	event := AgentEvent{
		Event:          EventConfigApplied,
		ConfigRevision: 7,
		Kernel:         KernelSingBox,
		Status:         EventStatusSuccess,
		Version:        "1.11.0",
		Message:        "applied",
		Detail:         "ok",
	}

	syncMsg := ServerConfigSync{
		ConfigRevision: 8,
		Snell: SnellConfig{
			Enabled:         true,
			Version:         SnellVersionV5,
			PublicPort:      8443,
			InnerPort:       31001,
			PSK:             "snell-psk",
			Obfs:            SnellObfsOff,
			TFO:             true,
			DNSIPPreference: DNSIPPrefPreferIPv4,
			STLSPassword:    "stls-pwd",
			STLSSNI:         "gateway.icloud.com",
		},
		SS: SSConfig{
			Enabled: true,
			TCPPort: 9443,
			UDPPort: 9443,
			Cipher:  CipherAES128GCM,
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
			STLSSNI: "gateway.icloud.com",
			Users: []SSUserEntry{
				{UserID: 1, Username: "alice", UPSK: "BBBBBBBBBBBBBBBBBBBBBB==", STLSPassword: "u-stls"},
			},
		},
		DNS: DNSConfig{
			UnlockEnabled: true,
			UnlockServer:  "1.2.3.4:3535",
			Rules:         []string{"netflix.com", "^ip.sb", "*.openai.com"},
			UpstreamDNS:   "1.1.1.1:53",
			LocalPort:     15353,
		},
	}

	update := ServerKernelUpdate{
		Kernel:      KernelShadowTLS,
		Version:     "v0.2.25",
		DownloadURL: "https://example.com/shadow-tls",
		SHA256:      "deadbeef",
	}

	ctl := ServerServiceCtl{Action: ServiceActionRestartSingBox}

	cases := []struct {
		name    string
		msgType string
		reqID   string
		payload any
		decode  func(Envelope) (any, error)
	}{
		{
			name:    "agent.hello",
			msgType: MsgTypeAgentHello,
			reqID:   "req-1",
			payload: hello,
			decode: func(e Envelope) (any, error) {
				var out AgentHello
				err := e.DecodePayload(&out)
				return out, err
			},
		},
		{
			name:    "agent.metrics",
			msgType: MsgTypeAgentMetrics,
			reqID:   "req-2",
			payload: metrics,
			decode: func(e Envelope) (any, error) {
				var out AgentMetrics
				err := e.DecodePayload(&out)
				return out, err
			},
		},
		{
			name:    "agent.event",
			msgType: MsgTypeAgentEvent,
			reqID:   "req-3",
			payload: event,
			decode: func(e Envelope) (any, error) {
				var out AgentEvent
				err := e.DecodePayload(&out)
				return out, err
			},
		},
		{
			name:    "server.config_sync",
			msgType: MsgTypeServerConfigSync,
			reqID:   "req-4",
			payload: syncMsg,
			decode: func(e Envelope) (any, error) {
				var out ServerConfigSync
				err := e.DecodePayload(&out)
				return out, err
			},
		},
		{
			name:    "server.kernel_update",
			msgType: MsgTypeServerKernelUpdate,
			reqID:   "req-5",
			payload: update,
			decode: func(e Envelope) (any, error) {
				var out ServerKernelUpdate
				err := e.DecodePayload(&out)
				return out, err
			},
		},
		{
			name:    "server.service_ctl",
			msgType: MsgTypeServerServiceCtl,
			reqID:   "req-6",
			payload: ctl,
			decode: func(e Envelope) (any, error) {
				var out ServerServiceCtl
				err := e.DecodePayload(&out)
				return out, err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := MarshalEnvelope(tc.msgType, tc.reqID, tc.payload)
			if err != nil {
				t.Fatalf("MarshalEnvelope failed: %v", err)
			}
			env, err := ParseEnvelope(raw)
			if err != nil {
				t.Fatalf("ParseEnvelope failed: %v", err)
			}
			if env.Type != tc.msgType {
				t.Fatalf("expected type %q, got %q", tc.msgType, env.Type)
			}
			if env.ReqID != tc.reqID {
				t.Fatalf("expected req_id %q, got %q", tc.reqID, env.ReqID)
			}
			got, err := tc.decode(env)
			if err != nil {
				t.Fatalf("DecodePayload failed: %v", err)
			}
			if !reflect.DeepEqual(got, tc.payload) {
				t.Fatalf("decoded payload mismatch:\ngot:  %+v\nwant: %+v", got, tc.payload)
			}
		})
	}
}

func TestEnvelopeEdgeCases(t *testing.T) {
	t.Run("nil payload defaults to empty JSON object", func(t *testing.T) {
		env, err := NewEnvelope(MsgTypeAgentEvent, "req-nil", nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(env.Payload) != "{}" {
			t.Fatalf("expected payload `{}`, got %q", string(env.Payload))
		}
	})

	t.Run("empty msgType fails", func(t *testing.T) {
		if _, err := NewEnvelope("", "req-1", nil); !errors.Is(err, ErrMissingMessageType) {
			t.Fatalf("expected ErrMissingMessageType, got %v", err)
		}
		if _, err := MarshalEnvelope("", "req-1", nil); !errors.Is(err, ErrMissingMessageType) {
			t.Fatalf("expected ErrMissingMessageType, got %v", err)
		}
	})

	t.Run("unmarshalable payload fails", func(t *testing.T) {
		if _, err := NewEnvelope(MsgTypeAgentEvent, "req-1", make(chan int)); err == nil {
			t.Fatal("expected error marshaling chan")
		}
	})

	t.Run("ParseEnvelope rejects invalid JSON or missing type", func(t *testing.T) {
		if _, err := ParseEnvelope([]byte(`{invalid`)); err == nil {
			t.Fatal("expected error for invalid JSON")
		}
		if _, err := ParseEnvelope([]byte(`{"req_id":"1","payload":{}}`)); !errors.Is(err, ErrMissingMessageType) {
			t.Fatalf("expected ErrMissingMessageType, got %v", err)
		}
	})

	t.Run("DecodePayload error cases", func(t *testing.T) {
		env := Envelope{Type: MsgTypeAgentHello, Payload: []byte(`{}`)}
		if err := env.DecodePayload(nil); !errors.Is(err, ErrNilDestination) {
			t.Fatalf("expected ErrNilDestination, got %v", err)
		}

		for _, empty := range [][]byte{nil, []byte(""), []byte("  "), []byte("null"), []byte(" null ")} {
			e := Envelope{Type: MsgTypeAgentHello, Payload: empty}
			var dst AgentHello
			if err := e.DecodePayload(&dst); !errors.Is(err, ErrEmptyPayload) {
				t.Fatalf("payload %q: expected ErrEmptyPayload, got %v", string(empty), err)
			}
		}

		badEnv := Envelope{Type: MsgTypeAgentHello, Payload: []byte(`{"cpu_cores":"not-int"}`)}
		var dst AgentHello
		if err := badEnv.DecodePayload(&dst); err == nil {
			t.Fatal("expected unmarshal error for mismatched field type")
		}
	})
}
