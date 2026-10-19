# dntrace

DN42-only traceroute, forked from [NTrace-core](https://github.com/nxtrace/NTrace-core) (v1.7.0) and stripped down for the DN42 network. GPL-3.0.

## What it does

```
$ dntrace 172.23.0.80
dntrace: geofeed updated from https://dn42.lianyi.me/dntrace/ (5644 rows)
IP Geo Data Provider: DN42
172.21.113.130 -> 172.23.0.80, 30 hops max, 28 byte packets, ICMP mode
1  172.20.14.42   AS4242423914   KIOUBIT-MNT   2.37 ms / 2.07 ms / 2.08 ms
2  172.23.0.80    AS64737        XUU-MNT       5.61 ms / 5.16 ms / 5.48 ms
```

No flags needed for DN42: every hop shows **IP, AS number, maintainer (MNT), PTR hostname and latency**. Country/city columns and all clearnet GeoIP providers were removed.

## How the data works

Per-hop attribution comes from a geofeed CSV generated from the DN42 registry (`inetnum`/`inet6num` + `route`/`route6` objects). On startup dntrace:

1. Uses the local cache (`~/.cache/dntrace/`) if it is fresh (< 24h),
2. otherwise races both mirrors and takes the fastest verified copy,
3. verifies SHA256 before swapping it in,
4. falls back to the stale cache, then to the snapshot embedded at build time.

Mirrors:

- `http://lianyi.dn42/dntrace/geofeed.csv` (inside DN42)
- `https://dn42.lianyi.me/dntrace/geofeed.csv` (clearnet)

Override with `DNTACE_GEOFEED_URLS` (comma-separated), `DNTACE_GEOFEED_TTL` (e.g. `12h`), `DNTACE_GEOFEED_CACHE`.

## Install

Download a build from [Releases](../../releases), or build it yourself:

```
go build -o dntrace .
```

Traceroute needs raw sockets: run with `sudo` or `sudo setcap cap_net_raw+ep ./dntrace`.

Linux (amd64/arm64), macOS (amd64/arm64) and Windows (amd64) builds are produced by GitHub Actions on every `v*` tag; the embedded geofeed snapshot is refreshed at build time.

## What was removed vs upstream

Clearnet GeoIP providers (IP.SB, IPInfo, IPInsight, IP-API, LeoMoeAPI, …), WebUI/deploy, Globalping, FastTrace, speedtest, tracemap upload, `--data-provider`/`--dn42` flags (DN42 is the only mode now), country/city display.
