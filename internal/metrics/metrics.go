// Package metrics is a small Prometheus text-format exporter built on the
// standard library: counters, gauges and histograms with fixed label names.
// Citadel exposes only bounded label values (route classes, AWS service and
// action names, status codes), so a dependency-free registry is enough and
// keeps the supply chain of a FIPS build small.
package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Registry holds metric families and renders them in text exposition format.
type Registry struct {
	mu       sync.Mutex
	families []family
	start    time.Time
}

type family interface {
	write(w io.Writer)
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{start: time.Now()} }

func (r *Registry) add(f family) {
	r.mu.Lock()
	r.families = append(r.families, f)
	r.mu.Unlock()
}

// Handler serves the registry plus Go runtime gauges.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		r.mu.Lock()
		fams := append([]family(nil), r.families...)
		r.mu.Unlock()
		for _, f := range fams {
			f.write(w)
		}
		writeRuntime(w, r.start)
	})
}

// ---- counters ---------------------------------------------------------------

// CounterVec is a counter partitioned by label values.
type CounterVec struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	values     map[string]float64
}

// NewCounterVec registers a counter family.
func (r *Registry) NewCounterVec(name, help string, labels ...string) *CounterVec {
	c := &CounterVec{name: name, help: help, labels: labels, values: map[string]float64{}}
	r.add(c)
	return c
}

// Inc adds one to the series with the given label values.
func (c *CounterVec) Inc(values ...string) { c.Add(1, values...) }

// Add adds v to the series with the given label values.
func (c *CounterVec) Add(v float64, values ...string) {
	k := labelKey(c.labels, values)
	c.mu.Lock()
	c.values[k] += v
	c.mu.Unlock()
}

func (c *CounterVec) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", c.name, c.help, c.name)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range sortedKeys(c.values) {
		fmt.Fprintf(w, "%s%s %s\n", c.name, k, formatFloat(c.values[k]))
	}
}

// ---- gauges -----------------------------------------------------------------

// GaugeVec is a gauge partitioned by label values.
type GaugeVec struct {
	name, help string
	labels     []string
	mu         sync.Mutex
	values     map[string]float64
}

// NewGaugeVec registers a gauge family.
func (r *Registry) NewGaugeVec(name, help string, labels ...string) *GaugeVec {
	g := &GaugeVec{name: name, help: help, labels: labels, values: map[string]float64{}}
	r.add(g)
	return g
}

// Set sets the series with the given label values.
func (g *GaugeVec) Set(v float64, values ...string) {
	k := labelKey(g.labels, values)
	g.mu.Lock()
	g.values[k] = v
	g.mu.Unlock()
}

func (g *GaugeVec) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", g.name, g.help, g.name)
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, k := range sortedKeys(g.values) {
		fmt.Fprintf(w, "%s%s %s\n", g.name, k, formatFloat(g.values[k]))
	}
}

// ---- histograms ---------------------------------------------------------------

// DefaultBuckets suit request latencies in seconds.
var DefaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// HistogramVec is a histogram partitioned by label values.
type HistogramVec struct {
	name, help string
	labels     []string
	buckets    []float64
	mu         sync.Mutex
	series     map[string]*histSeries
}

type histSeries struct {
	counts []uint64 // per bucket, non-cumulative
	count  uint64
	sum    float64
}

// NewHistogramVec registers a histogram family.
func (r *Registry) NewHistogramVec(name, help string, buckets []float64, labels ...string) *HistogramVec {
	h := &HistogramVec{name: name, help: help, labels: labels, buckets: buckets, series: map[string]*histSeries{}}
	r.add(h)
	return h
}

// Observe records v for the series with the given label values.
func (h *HistogramVec) Observe(v float64, values ...string) {
	k := labelKey(h.labels, values)
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.series[k]
	if s == nil {
		s = &histSeries{counts: make([]uint64, len(h.buckets))}
		h.series[k] = s
	}
	for i, b := range h.buckets {
		if v <= b {
			s.counts[i]++
			break
		}
	}
	s.count++
	s.sum += v
}

func (h *HistogramVec) write(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", h.name, h.help, h.name)
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := make([]string, 0, len(h.series))
	for k := range h.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := h.series[k]
		var cum uint64
		for i, b := range h.buckets {
			cum += s.counts[i]
			fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, withLabel(k, "le", formatFloat(b)), cum)
		}
		fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, withLabel(k, "le", "+Inf"), s.count)
		fmt.Fprintf(w, "%s_sum%s %s\n", h.name, k, formatFloat(s.sum))
		fmt.Fprintf(w, "%s_count%s %d\n", h.name, k, s.count)
	}
}

// ---- helpers --------------------------------------------------------------------

func labelKey(names, values []string) string {
	if len(names) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n)
		b.WriteString(`="`)
		b.WriteString(escape(v))
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String()
}

func withLabel(key, name, value string) string {
	pair := name + `="` + value + `"`
	if key == "" {
		return "{" + pair + "}"
	}
	return key[:len(key)-1] + "," + pair + "}"
}

func escape(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return strings.ReplaceAll(v, `"`, `\"`)
}

func sortedKeys(m map[string]float64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func writeRuntime(w io.Writer, start time.Time) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Fprintf(w, "# HELP go_goroutines Number of goroutines.\n# TYPE go_goroutines gauge\ngo_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP go_memstats_heap_alloc_bytes Heap bytes allocated and in use.\n# TYPE go_memstats_heap_alloc_bytes gauge\ngo_memstats_heap_alloc_bytes %d\n", m.HeapAlloc)
	fmt.Fprintf(w, "# HELP go_memstats_sys_bytes Bytes obtained from the OS.\n# TYPE go_memstats_sys_bytes gauge\ngo_memstats_sys_bytes %d\n", m.Sys)
	fmt.Fprintf(w, "# HELP go_gc_cycles_total Completed GC cycles.\n# TYPE go_gc_cycles_total counter\ngo_gc_cycles_total %d\n", m.NumGC)
	fmt.Fprintf(w, "# HELP process_uptime_seconds Seconds since the process started.\n# TYPE process_uptime_seconds gauge\nprocess_uptime_seconds %s\n", formatFloat(time.Since(start).Seconds()))
}
