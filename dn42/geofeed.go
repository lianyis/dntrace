package dn42

import (
	_ "embed"
	"encoding/csv"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

//go:embed geofeed.snapshot.csv
var snapshotCSV string

// GeoFeedRow is one row of the dntrace geofeed dataset:
// prefix,asn,mnt,descr  (e.g. 172.21.113.128/27,4242421886,LY-MNT,LY-IPV4)
type GeoFeedRow struct {
	IPNet *net.IPNet
	ASN   string
	MNT   string
	Descr string
}

var (
	mu   sync.RWMutex
	rows []GeoFeedRow // sorted by prefix length, longest first
)

// parseCSV parses the 4-column geofeed format, skipping # comment lines.
func parseCSV(r io.Reader) ([]GeoFeedRow, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	var out []GeoFeedRow
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(rec) == 0 {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(rec[0]), "#") {
			continue
		}
		if len(rec) < 4 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(strings.TrimSpace(rec[0]))
		if err != nil {
			continue
		}
		out = append(out, GeoFeedRow{
			IPNet: ipnet,
			ASN:   strings.TrimSpace(rec[1]),
			MNT:   strings.TrimSpace(rec[2]),
			Descr: strings.TrimSpace(rec[3]),
		})
	}
	// longest prefix first for LPM
	sort.Slice(out, func(i, j int) bool {
		oi, oj := ones(out[i].IPNet.Mask), ones(out[j].IPNet.Mask)
		if oi != oj {
			return oi > oj
		}
		return out[i].IPNet.String() < out[j].IPNet.String()
	})
	return out, nil
}

func ones(m net.IPMask) int {
	o, _ := m.Size()
	return o
}

// loadSnapshot loads the build-time embedded dataset.
func loadSnapshot() error {
	parsed, err := parseCSV(strings.NewReader(snapshotCSV))
	if err != nil {
		return err
	}
	mu.Lock()
	rows = parsed
	mu.Unlock()
	return nil
}

// loadFile loads the dataset from a CSV file on disk.
func loadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	parsed, err := parseCSV(f)
	if err != nil {
		return err
	}
	mu.Lock()
	rows = parsed
	mu.Unlock()
	return nil
}

// GetGeoFeed returns the longest-prefix-match row for ip, or false.
func GetGeoFeed(ipStr string) (GeoFeedRow, bool) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return GeoFeedRow{}, false
	}
	mu.RLock()
	defer mu.RUnlock()
	for _, row := range rows {
		if row.IPNet.Contains(ip) {
			return row, true
		}
	}
	return GeoFeedRow{}, false
}

// RowCount returns the number of loaded rows (for diagnostics/tests).
func RowCount() int {
	mu.RLock()
	defer mu.RUnlock()
	return len(rows)
}
