package printer

import (
	"fmt"
	"net"
	"strings"

	"github.com/fatih/color"

	"github.com/lianyis/dntrace/config"
	"github.com/lianyis/dntrace/trace"
	"github.com/lianyis/dntrace/util"
)

var version = config.Version
var buildDate = config.BuildDate
var commitID = config.CommitID

func Version() {
	fmt.Fprintf(color.Output, "%s %s %s %s\n",
		color.New(color.FgWhite, color.Bold).Sprintf("%s", "dntrace"),
		color.New(color.FgHiBlack, color.Bold).Sprintf("%s", version),
		color.New(color.FgHiBlack, color.Bold).Sprintf("%s", buildDate),
		color.New(color.FgHiBlack, color.Bold).Sprintf("%s", commitID),
	)
}

func CopyRight() {
	fmt.Fprintf(color.Output, "\n%s\n%s\n",
		color.New(color.FgCyan, color.Bold).Sprintf("%s", "dntrace - DN42 traceroute"),
		color.New(color.FgHiBlack, color.Bold).Sprintf("%s", "Forked from NTrace-core (GPL-3.0), stripped down for DN42-only use."),
	)
}

func PrintTraceRouteNav(ip net.IP, domain string, dataOrigin string, maxHops int, packetSize int, srcAddr string, mode string) {
	fmt.Println("IP Geo Data Provider: " + dataOrigin)
	if srcAddr == "" {
		srcAddr = "traceroute to"
	} else {
		srcAddr += " ->"
	}
	if !util.EnableHidDstIP {
		if ip.String() == domain {
			fmt.Printf("%s %s, %d hops max, %s, %s mode\n", srcAddr, ip.String(), maxHops, trace.FormatPacketSizeLabel(packetSize), strings.ToUpper(mode))
		} else {
			fmt.Printf("%s %s (%s), %d hops max, %s, %s mode\n", srcAddr, ip.String(), domain, maxHops, trace.FormatPacketSizeLabel(packetSize), strings.ToUpper(mode))
		}
	} else {
		fmt.Printf("%s %s, %d hops max, %s, %s mode\n", srcAddr, util.HideIPPart(ip.String()), maxHops, trace.FormatPacketSizeLabel(packetSize), strings.ToUpper(mode))
	}
}

func applyLangSetting(h *trace.Hop) {
	if h.Geo == nil || h.Geo.Source == trace.PendingGeoSource {
		return
	}
	// dntrace: DN42 geofeed carries no country/city data; leave as-is.
	if h.Geo.Source == "DN42" {
		return
	}
	if len(h.Geo.Country) <= 1 {
		// 打印 h.Geo
		if h.Geo.Whois != "" {
			h.Geo.Country = h.Geo.Whois
		} else {
			if h.Geo.Source != "LeoMoeAPI" {
				h.Geo.Country = "网络故障"
				h.Geo.CountryEn = "Network Error"
			} else {
				h.Geo.Country = "未知"
				h.Geo.CountryEn = "Unknown"
			}
		}
	}

	if h.Lang == "en" {
		if h.Geo.Country == "Anycast" {
		} else if h.Geo.Prov == "骨干网" {
			h.Geo.Prov = "BackBone"
		} else if h.Geo.ProvEn == "" {
			if h.Geo.CountryEn != "" {
				h.Geo.Country = h.Geo.CountryEn
			}
		} else {
			if h.Geo.CityEn == "" {
				h.Geo.Country = h.Geo.ProvEn
				h.Geo.Prov = h.Geo.CountryEn
				h.Geo.City = ""
			} else {
				h.Geo.Country = h.Geo.CityEn
				h.Geo.Prov = h.Geo.ProvEn
				h.Geo.City = h.Geo.CountryEn
			}
		}
	}
}
