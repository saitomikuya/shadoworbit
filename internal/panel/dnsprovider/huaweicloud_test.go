package dnsprovider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHuaweiCloudSigningAndListZones(t *testing.T) {
	var gotAuth, gotDate, gotContentType, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotDate = r.Header.Get("X-Sdk-Date")
		gotContentType = r.Header.Get("Content-Type")
		gotQuery = r.URL.RawQuery

		if r.Method != http.MethodGet || r.URL.Path != "/v2/zones" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"zones": []map[string]any{
				{
					"id":         "z-1",
					"name":       "example.com.",
					"status":     "ACTIVE",
					"ttl":        300,
					"record_num": 4,
				},
			},
		})
	}))
	defer srv.Close()

	fixedNow := time.Date(2026, 11, 28, 10, 0, 0, 0, time.UTC)
	cl, err := NewHuaweiCloudClient(srv.URL, "AKTEST123", "SKSECRET456", WithNow(func() time.Time { return fixedNow }))
	if err != nil {
		t.Fatalf("NewHuaweiCloudClient failed: %v", err)
	}

	zones, err := cl.ListPublicZones(context.Background())
	if err != nil {
		t.Fatalf("ListPublicZones failed: %v", err)
	}
	if len(zones) != 1 || zones[0].ID != "z-1" || zones[0].Name != "example.com" {
		t.Fatalf("unexpected zones: %+v", zones)
	}
	if gotDate != "20261128T100000Z" {
		t.Fatalf("unexpected X-Sdk-Date: %q", gotDate)
	}
	if gotContentType != "application/json" {
		t.Fatalf("unexpected Content-Type: %q", gotContentType)
	}
	if !strings.Contains(gotQuery, "type=public") {
		t.Fatalf("expected type=public query, got %q", gotQuery)
	}
	if !strings.HasPrefix(gotAuth, "SDK-HMAC-SHA256 Access=AKTEST123, SignedHeaders=content-type;host;x-sdk-date, Signature=") {
		t.Fatalf("unexpected Authorization header: %q", gotAuth)
	}
	if buildCanonicalURI("/v2/zones") != "/v2/zones/" {
		t.Fatalf("expected trailing slash in CanonicalURI, got %q", buildCanonicalURI("/v2/zones"))
	}
}

func TestHuaweiCloudSyncARecordsSingleAndWeighted(t *testing.T) {
	var mu sync.Mutex
	type rec struct {
		ID      string   `json:"id"`
		Name    string   `json:"name"`
		Type    string   `json:"type"`
		TTL     int      `json:"ttl"`
		Records []string `json:"records"`
		Line    string   `json:"line"`
		Weight  *int     `json:"weight,omitempty"`
	}
	records := map[string]rec{}
	seq := 0
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path)

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2.1/zones/z1/recordsets":
			list := make([]rec, 0, len(records))
			for _, item := range records {
				list = append(list, item)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"recordsets": list})

		case r.Method == http.MethodPost && r.URL.Path == "/v2.1/zones/z1/recordsets":
			body, _ := io.ReadAll(r.Body)
			var req recordSetMutateBody
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatal(err)
			}
			seq++
			id := "rs-" + string(rune('0'+seq))
			item := rec{
				ID:      id,
				Name:    req.Name,
				Type:    req.Type,
				TTL:     req.TTL,
				Records: req.Records,
				Line:    req.Line,
				Weight:  req.Weight,
			}
			records[id] = item
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(item)

		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v2.1/zones/z1/recordsets/"):
			id := strings.TrimPrefix(r.URL.Path, "/v2.1/zones/z1/recordsets/")
			body, _ := io.ReadAll(r.Body)
			var req recordSetMutateBody
			if err := json.Unmarshal(body, &req); err != nil {
				t.Fatal(err)
			}
			item := records[id]
			item.TTL = req.TTL
			item.Records = req.Records
			item.Weight = req.Weight
			records[id] = item
			_ = json.NewEncoder(w).Encode(item)

		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v2.1/zones/z1/recordsets/"):
			id := strings.TrimPrefix(r.URL.Path, "/v2.1/zones/z1/recordsets/")
			delete(records, id)
			w.WriteHeader(http.StatusOK)

		default:
			t.Fatalf("unexpected api call: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cl, err := NewHuaweiCloudClient(srv.URL, "ak", "sk")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// 1. Initial single-IP create.
	res, err := cl.SyncARecords(ctx, "z1", "ali.example.com", 60, false, []DesiredRecord{{IP: "1.1.1.1"}})
	if err != nil {
		t.Fatalf("initial SyncARecords failed: %v", err)
	}
	if len(res) != 1 || res[0].IP != "1.1.1.1" {
		t.Fatalf("unexpected synced result: %+v", res)
	}

	// 2. Identical sync should be a no-op (only GET, no PUT/POST).
	callsBefore := len(calls)
	_, err = cl.SyncARecords(ctx, "z1", "ali.example.com", 60, false, []DesiredRecord{{IP: "1.1.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls)-callsBefore != 1 {
		t.Fatalf("expected no-op single GET, got calls: %v", calls[callsBefore:])
	}

	// 3. Switch to second IP -> PUT in place.
	res, err = cl.SyncARecords(ctx, "z1", "ali.example.com", 60, false, []DesiredRecord{{IP: "2.2.2.2"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].IP != "2.2.2.2" {
		t.Fatalf("expected 2.2.2.2 after update, got %+v", res)
	}

	// 4. Transition to weighted_multi -> deletes plain record, creates 2 weighted records.
	res, err = cl.SyncARecords(ctx, "z1", "ali.example.com", 60, true, []DesiredRecord{
		{IP: "1.1.1.1", Weight: 70},
		{IP: "2.2.2.2", Weight: 30},
	})
	if err != nil {
		t.Fatalf("weighted SyncARecords failed: %v", err)
	}
	if len(res) != 2 || len(records) != 2 {
		t.Fatalf("expected 2 weighted records, got res=%+v map=%+v", res, records)
	}

	// 5. Transition back to single-IP -> deletes weighted records, creates 1 plain record.
	res, err = cl.SyncARecords(ctx, "z1", "ali.example.com", 60, false, []DesiredRecord{{IP: "1.1.1.1"}})
	if err != nil {
		t.Fatalf("back to single-IP failed: %v", err)
	}
	if len(res) != 1 || len(records) != 1 {
		t.Fatalf("expected 1 plain record, got res=%+v map=%+v", res, records)
	}
}
