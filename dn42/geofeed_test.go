package dn42

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCSV = `# dntrace geofeed v1: prefix,asn,mnt,descr
172.20.0.0/14,4242420000,DN42-MNT,DN42-TEST
172.21.113.128/27,4242421886,LY-MNT,LY-IPV4
10.0.0.0/8,,DN42-MNT,BLK-FREIFUNK
`

func loadTestData(t *testing.T) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "geofeed.csv")
	if err := os.WriteFile(p, []byte(testCSV), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loadFile(p); err != nil {
		t.Fatal(err)
	}
}

func TestParseCSVSkipsComments(t *testing.T) {
	rows, err := parseCSV(strings.NewReader(testCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want 3", len(rows))
	}
}

func TestGetGeoFeedLongestMatch(t *testing.T) {
	loadTestData(t)
	// 172.21.113.130 matches both /14 and /27 -> /27 wins
	row, ok := GetGeoFeed("172.21.113.130")
	if !ok {
		t.Fatal("no match")
	}
	if row.ASN != "4242421886" || row.MNT != "LY-MNT" || row.Descr != "LY-IPV4" {
		t.Fatalf("wrong row: %+v", row)
	}
	// 172.20.14.42 matches only /14
	row, ok = GetGeoFeed("172.20.14.42")
	if !ok || row.ASN != "4242420000" {
		t.Fatalf("wrong row: %+v %v", row, ok)
	}
	// row without ASN keeps MNT
	row, ok = GetGeoFeed("10.1.2.3")
	if !ok || row.ASN != "" || row.MNT != "DN42-MNT" {
		t.Fatalf("wrong row: %+v %v", row, ok)
	}
	// no match
	if _, ok = GetGeoFeed("192.0.2.1"); ok {
		t.Fatal("unexpected match")
	}
	// invalid ip
	if _, ok = GetGeoFeed("not-an-ip"); ok {
		t.Fatal("unexpected match for invalid ip")
	}
}

func TestLoadSnapshot(t *testing.T) {
	if err := loadSnapshot(); err != nil {
		t.Fatal(err)
	}
	if RowCount() == 0 {
		t.Fatal("snapshot loaded 0 rows")
	}
	row, ok := GetGeoFeed("172.21.113.130")
	if !ok {
		t.Fatal("snapshot: no match for 172.21.113.130")
	}
	if row.ASN != "4242421886" || row.MNT != "LY-MNT" {
		t.Fatalf("snapshot wrong row: %+v", row)
	}
}
