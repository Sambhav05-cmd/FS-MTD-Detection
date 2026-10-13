// A standard-library-only workload for native, mounted FUSE, and LSM reads.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"sync"
	"syscall"
	"time"
)

type result struct {
	Mode       string  `json:"mode"`
	Block      int     `json:"block_bytes"`
	Workers    int     `json:"workers"`
	Operations int64   `json:"operations"`
	Seconds    float64 `json:"seconds"`
	MiBPerSec  float64 `json:"mib_per_sec"`
	P50US      float64 `json:"sampled_p50_us"`
	P95US      float64 `json:"sampled_p95_us"`
	P99US      float64 `json:"sampled_p99_us"`
	Samples    int     `json:"latency_samples"`
}

func main() {
	path := flag.String("file", "", "existing regular fixture file")
	mode := flag.String("mode", "native", "result label, assigned by runner")
	block := flag.Int("block", 4096, "read size")
	workers := flag.Int("workers", 1, "concurrent readers")
	duration := flag.Duration("duration", time.Second, "measurement duration")
	flag.Parse()
	if *path == "" || *block <= 0 || *workers <= 0 || *duration <= 0 {
		panic("invalid arguments")
	}
	runtime.GOMAXPROCS(*workers)
	files := make([]*os.File, *workers)
	var size int64
	for i := range files {
		f, err := os.Open(*path)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() || st.Size() < int64(*block) {
			panic("invalid fixture size/type")
		}
		size = st.Size() / int64(*block) * int64(*block)
		files[i] = f
	}
	// Explicitly warm the same backing bytes before all measurement variants.
	warm := make([]byte, *block)
	for off := int64(0); off < size; off += int64(*block) {
		if n, err := syscall.Pread(int(files[0].Fd()), warm, off); err != nil || n != *block {
			panic(fmt.Sprintf("warm read: %d %v", n, err))
		}
	}
	var ready, done sync.WaitGroup
	start := make(chan struct{})
	ready.Add(*workers)
	done.Add(*workers)
	counts := make([]int64, *workers)
	latencies := make([][]float64, *workers)
	errors := make(chan error, *workers)
	var deadline time.Time
	for w := range files {
		go func(w int) {
			defer done.Done()
			buf := make([]byte, *block)
			samples := make([]float64, 0, 16384)
			ready.Done()
			<-start
			var count int64
			off := int64(w**block) % size
			for {
				if count%64 == 0 && time.Now().After(deadline) {
					break
				}
				sample := count%256 == 0 && len(samples) < cap(samples)
				var began time.Time
				if sample {
					began = time.Now()
				}
				n, err := syscall.Pread(int(files[w].Fd()), buf, off)
				if sample {
					samples = append(samples, float64(time.Since(began).Nanoseconds())/1000)
				}
				if err != nil || n != *block {
					errors <- fmt.Errorf("read: n=%d err=%v", n, err)
					return
				}
				count++
				off = (off + int64(*block)) % size
			}
			counts[w], latencies[w] = count, samples
		}(w)
	}
	ready.Wait()
	began := time.Now()
	deadline = began.Add(*duration)
	close(start)
	done.Wait()
	elapsed := time.Since(began).Seconds()
	close(errors)
	for err := range errors {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var operations int64
	var samples []float64
	for w, count := range counts {
		operations += count
		samples = append(samples, latencies[w]...)
	}
	sort.Float64s(samples)
	if len(samples) == 0 {
		panic("no samples")
	}
	q := func(p float64) float64 { return samples[int(float64(len(samples)-1)*p)] }
	r := result{*mode, *block, *workers, operations, elapsed, float64(operations) * float64(*block) / elapsed / (1 << 20), q(.5), q(.95), q(.99), len(samples)}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		panic(err)
	}
}
