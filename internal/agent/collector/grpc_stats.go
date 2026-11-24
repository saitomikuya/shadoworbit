package collector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	statsQueryMethod  = "/v2ray.core.app.stats.command.StatsService/QueryStats"
	statsUserPattern  = "user>>>"
	defaultRPCTimeout = 5 * time.Second
)

// rawProtoCodec sends and receives raw protobuf wire bytes using the "proto" content-type subtype.
type rawProtoCodec struct{}

func (rawProtoCodec) Name() string { return "proto" }

func (rawProtoCodec) Marshal(v any) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return x, nil
	case *[]byte:
		if x == nil {
			return nil, nil
		}
		return *x, nil
	default:
		return nil, fmt.Errorf("rawProtoCodec: unsupported marshal type %T", v)
	}
}

func (rawProtoCodec) Unmarshal(data []byte, v any) error {
	dst, ok := v.(*[]byte)
	if !ok || dst == nil {
		return fmt.Errorf("rawProtoCodec: unsupported unmarshal target %T", v)
	}
	// Copy bytes because grpc pooled mem.Buffer backing data is freed upon return.
	*dst = append((*dst)[:0], data...)
	return nil
}

type rawStat struct {
	Name  string
	Value int64
}

// encodeQueryStatsRequest encodes v2ray.core.app.stats.command.QueryStatsRequest.
// Both field 1 (pattern, legacy V2Ray) and field 3 (patterns, sing-box) are populated
// alongside field 2 (reset). Field 4 (regexp) is omitted (defaults to false).
func encodeQueryStatsRequest(pattern string, reset bool) []byte {
	var b []byte
	if pattern != "" {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendString(b, pattern)
	}
	if reset {
		b = protowire.AppendTag(b, 2, protowire.VarintType)
		b = protowire.AppendVarint(b, protowire.EncodeBool(true))
	}
	if pattern != "" {
		b = protowire.AppendTag(b, 3, protowire.BytesType)
		b = protowire.AppendString(b, pattern)
	}
	return b
}

func decodeQueryStatsResponse(b []byte) ([]rawStat, error) {
	var out []rawStat
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		b = b[n:]
		if num == 1 && typ == protowire.BytesType {
			msgBytes, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			b = b[m:]
			st, err := decodeStat(msgBytes)
			if err != nil {
				return nil, err
			}
			out = append(out, st)
			continue
		}
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		b = b[m:]
	}
	return out, nil
}

func decodeStat(b []byte) (rawStat, error) {
	var st rawStat
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return st, protowire.ParseError(n)
		}
		b = b[n:]
		switch {
		case num == 1 && typ == protowire.BytesType:
			v, m := protowire.ConsumeString(b)
			if m < 0 {
				return st, protowire.ParseError(m)
			}
			st.Name = v
			b = b[m:]
		case num == 2 && typ == protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return st, protowire.ParseError(m)
			}
			// Proto3 int64 uses standard two's complement encoding, NOT ZigZag.
			st.Value = int64(v)
			b = b[m:]
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return st, protowire.ParseError(m)
			}
			b = b[m:]
		}
	}
	return st, nil
}

func parseUserTrafficStat(name string) (username string, isUplink bool, ok bool) {
	const (
		prefix = "user>>>"
		upSfx  = ">>>traffic>>>uplink"
		dnSfx  = ">>>traffic>>>downlink"
	)
	if !strings.HasPrefix(name, prefix) {
		return "", false, false
	}
	rest := strings.TrimPrefix(name, prefix)
	if strings.HasSuffix(rest, upSfx) {
		u := strings.TrimSuffix(rest, upSfx)
		return u, true, u != ""
	}
	if strings.HasSuffix(rest, dnSfx) {
		u := strings.TrimSuffix(rest, dnSfx)
		return u, false, u != ""
	}
	return "", false, false
}

func (c *Collector) pollStats(ctx context.Context) error {
	if c.opts.StatsAddr == "" {
		return nil
	}

	c.userMu.RLock()
	enabled := c.statsEnabled
	activeSnapshot := make(map[string]int64, len(c.activeUsers))
	for k, v := range c.activeUsers {
		activeSnapshot[k] = v
	}
	c.userMu.RUnlock()

	if !enabled {
		return nil
	}

	reqBytes := encodeQueryStatsRequest(statsUserPattern, true)
	var respBytes []byte

	rpcCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		rpcCtx, cancel = context.WithTimeout(ctx, defaultRPCTimeout)
		defer cancel()
	}

	c.statsMu.Lock()
	conn, err := c.ensureGRPCConnLocked()
	c.statsMu.Unlock()
	if err != nil {
		return err
	}
	err = conn.Invoke(rpcCtx, statsQueryMethod, reqBytes, &respBytes, grpc.ForceCodec(rawProtoCodec{}))
	if err != nil {
		return fmt.Errorf("grpc QueryStats %q: %w", c.opts.StatsAddr, err)
	}

	stats, err := decodeQueryStatsResponse(respBytes)
	if err != nil {
		return fmt.Errorf("decode QueryStatsResponse: %w", err)
	}

	aggregated := make(map[string]walUserDelta)
	for _, st := range stats {
		if st.Value < 0 {
			c.logger.Warn("ignoring negative stat value", "name", st.Name, "value", st.Value)
			continue
		}
		if st.Value == 0 {
			continue
		}
		username, isUplink, ok := parseUserTrafficStat(st.Name)
		if !ok {
			continue
		}
		entry := aggregated[username]
		entry.Username = username
		if uid, found := activeSnapshot[username]; found {
			entry.UserID = uid
		}
		if isUplink {
			entry.UpBytes += uint64(st.Value)
		} else {
			entry.DownBytes += uint64(st.Value)
		}
		aggregated[username] = entry
	}

	if len(aggregated) > 0 {
		if err := c.addUserDeltas(aggregated, activeSnapshot); err != nil {
			return fmt.Errorf("persist user deltas: %w", err)
		}
	}
	return nil
}

func (c *Collector) ensureGRPCConnLocked() (*grpc.ClientConn, error) {
	if c.grpcConn != nil && c.grpcTarget == c.opts.StatsAddr {
		return c.grpcConn, nil
	}
	if c.grpcConn != nil {
		_ = c.grpcConn.Close()
		c.grpcConn = nil
		c.grpcTarget = ""
	}
	conn, err := grpc.NewClient(
		c.opts.StatsAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawProtoCodec{})),
	)
	if err != nil {
		return nil, fmt.Errorf("create grpc client for %q: %w", c.opts.StatsAddr, err)
	}
	c.grpcConn = conn
	c.grpcTarget = c.opts.StatsAddr
	return conn, nil
}

func (c *Collector) closeGRPC() {
	c.statsMu.Lock()
	defer c.statsMu.Unlock()
	if c.grpcConn != nil {
		_ = c.grpcConn.Close()
		c.grpcConn = nil
		c.grpcTarget = ""
	}
}
