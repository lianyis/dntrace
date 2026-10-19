package dn42

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultSources are the dataset mirrors, tried in race order.
// The first URL is DN42-internal, the second is clearnet.
var DefaultSources = []string{
	"http://geofeed.lianyi.dn42/dntrace/",
	"http://dn42.lianyi.me/dntrace/",
}

const (
	csvFileName  = "geofeed.csv"
	shaFileName  = "geofeed.csv.sha256"
	metaFileName = "geofeed.meta.json"

	defaultTTL = 24 * time.Hour
	fetchTO    = 20 * time.Second
)

// cacheMeta tracks the local cache state.
type cacheMeta struct {
	SHA256    string `json:"sha256"`
	FetchedAt string `json:"fetched_at"`
}

func cacheDir() string {
	if d := os.Getenv("DNTACE_GEOFEED_CACHE"); d != "" {
		return d
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "dntrace")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".cache", "dntrace")
	}
	return filepath.Join(home, ".cache", "dntrace")
}

func sources() []string {
	if s := os.Getenv("DNTACE_GEOFEED_URLS"); s != "" {
		var out []string
		for _, u := range strings.Split(s, ",") {
			if u = strings.TrimSpace(u); u != "" {
				if !strings.HasSuffix(u, "/") {
					u += "/"
				}
				out = append(out, u)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return DefaultSources
}

func ttl() time.Duration {
	if s := os.Getenv("DNTACE_GEOFEED_TTL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			return d
		}
	}
	return defaultTTL
}

func readMeta(dir string) (cacheMeta, bool) {
	var m cacheMeta
	b, err := os.ReadFile(filepath.Join(dir, metaFileName))
	if err != nil {
		return m, false
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, false
	}
	return m, m.SHA256 != "" && m.FetchedAt != ""
}

func metaFresh(m cacheMeta) bool {
	t, err := time.Parse(time.RFC3339, m.FetchedAt)
	if err != nil {
		return false
	}
	return time.Since(t) < ttl()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func atomicWrite(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// fetchURL downloads a single file with a timeout.
func fetchURL(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // 8MB cap
}

// raceFetch returns the first successful download across sources.
func raceFetch(ctx context.Context, client *http.Client, srcs []string, file string) (body []byte, winner string, err error) {
	type result struct {
		body []byte
		src  string
		err  error
	}
	ch := make(chan result, len(srcs))
	var wg sync.WaitGroup
	for _, s := range srcs {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()
			b, e := fetchURL(ctx, client, src+file)
			select {
			case ch <- result{b, src, e}:
			case <-ctx.Done():
			}
		}(s)
	}
	go func() { wg.Wait(); close(ch) }()
	var errs []string
	for r := range ch {
		if r.err == nil {
			return r.body, r.src, nil
		}
		errs = append(errs, r.src+": "+r.err.Error())
	}
	return nil, "", fmt.Errorf("all sources failed for %s: %s", file, strings.Join(errs, "; "))
}

// downloadVerified fetches csv+sha256 (sha from the same winning source) and
// verifies integrity. Falls back to other sources on mismatch.
func downloadVerified(ctx context.Context, client *http.Client, srcs []string) ([]byte, string, error) {
	remaining := append([]string{}, srcs...)
	var lastErr error
	for len(remaining) > 0 {
		body, winner, err := raceFetch(ctx, client, remaining, csvFileName)
		if err != nil {
			return nil, "", err
		}
		shaBody, err := fetchURL(ctx, client, winner+shaFileName)
		if err != nil {
			lastErr = fmt.Errorf("%s sha256 fetch: %w", winner, err)
		} else {
			want := strings.Fields(string(shaBody))[0]
			got := sha256Hex(body)
			if want == got {
				return body, winner, nil
			}
			lastErr = fmt.Errorf("%s checksum mismatch", winner)
		}
		// drop the bad source and retry
		kept := remaining[:0]
		for _, s := range remaining {
			if s != winner {
				kept = append(kept, s)
			}
		}
		remaining = kept
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no sources left")
	}
	return nil, "", lastErr
}

// EnsureData makes sure fresh geofeed data is loaded:
// fresh cache -> use it; stale/missing -> download (race, verified);
// download failure -> stale cache if any, else embedded snapshot.
// It never fails hard: worst case the tool runs with the snapshot.
func EnsureData(ctx context.Context) error {
	dir := cacheDir()
	csvPath := filepath.Join(dir, csvFileName)

	if m, ok := readMeta(dir); ok && metaFresh(m) {
		if b, err := os.ReadFile(csvPath); err == nil && sha256Hex(b) == m.SHA256 {
			return loadFile(csvPath)
		}
	}

	fetchCtx, cancel := context.WithTimeout(ctx, fetchTO)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second}
	if body, winner, err := downloadVerified(fetchCtx, client, sources()); err == nil {
		sum := sha256Hex(body)
		if werr := atomicWrite(csvPath, body); werr == nil {
			meta, _ := json.Marshal(cacheMeta{
				SHA256:    sum,
				FetchedAt: time.Now().UTC().Format(time.RFC3339),
			})
			_ = atomicWrite(filepath.Join(dir, metaFileName), meta)
			fmt.Fprintf(os.Stderr, "dntrace: geofeed updated from %s (%d rows)\n", winner, countRows(body))
		} else {
			fmt.Fprintf(os.Stderr, "dntrace: geofeed cache write failed: %v\n", werr)
		}
		return loadFile(csvPath)
	} else {
		fmt.Fprintf(os.Stderr, "dntrace: geofeed download failed: %v\n", err)
	}

	// fall back to (possibly stale) cache
	if _, err := os.Stat(csvPath); err == nil {
		fmt.Fprintf(os.Stderr, "dntrace: using stale cached geofeed\n")
		if lerr := loadFile(csvPath); lerr == nil {
			return nil
		}
	}
	fmt.Fprintf(os.Stderr, "dntrace: using embedded geofeed snapshot\n")
	return loadSnapshot()
}

func countRows(body []byte) int {
	n := 0
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			n++
		}
	}
	return n
}
