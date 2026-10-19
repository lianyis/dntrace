package ipgeo

import (
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

// GetSource returns the DN42 source. dntrace is DN42-only; the name
// argument is kept for call-site compatibility and ignored.
func GetSource(_ string) Source {
	return DN42
}

func disableGeoIP(string, time.Duration, string, bool) (*IPGeoData, error) {
	return &IPGeoData{}, nil
}
