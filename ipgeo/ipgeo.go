package ipgeo

import (
	"strings"
	"time"
)

type IPGeoData struct {
	IP        string              `json:"ip"`
	Asnumber  string              `json:"asnumber"`
	Country   string              `json:"country"`
	CountryEn string              `json:"country_en"`
	Prov      string              `json:"prov"`
	ProvEn    string              `json:"prov_en"`
	City      string              `json:"city"`
	CityEn    string              `json:"city_en"`
	District  string              `json:"district"`
	Owner     string              `json:"owner"`
	Isp       string              `json:"isp"`
	Domain    string              `json:"domain"`
	Whois     string              `json:"whois"`
	Lat       float64             `json:"lat"`
	Lng       float64             `json:"lng"`
	Prefix    string              `json:"prefix"`
	Router    map[string][]string `json:"router"`
	Source    string              `json:"source"`
}

type Source = func(ip string, timeout time.Duration, lang string, maptrace bool) (*IPGeoData, error)

// GetSource returns the DN42 source, or the no-op source when asked to
// disable GeoIP. dntrace is DN42-only; any other name maps to DN42.
func GetSource(name string) Source {
	if strings.EqualFold(name, "disable-geoip") {
		return disableGeoIP
	}
	return DN42
}

func disableGeoIP(string, time.Duration, string, bool) (*IPGeoData, error) {
	return &IPGeoData{}, nil
}
