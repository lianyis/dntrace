package ipgeo

import (
	"time"

	"github.com/lianyis/dntrace/dn42"
)

// DN42 is the only GeoIP source in dntrace: ASN + MNT from the local geofeed.
func DN42(ip string, _ time.Duration, _ string, _ bool) (*IPGeoData, error) {
	data := &IPGeoData{Source: "DN42"}
	if geo, find := dn42.GetGeoFeed(ip); find {
		data.Asnumber = geo.ASN
		data.Owner = geo.MNT
	}
	return data, nil
}
