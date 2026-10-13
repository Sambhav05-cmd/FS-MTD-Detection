# Read path experiment

This is a read-only prototype and comparison harness, not a complete detector
migration. The existing write/entropy/classifier code is retained. The only
production changes are CLI options for mount/backing/log paths and allow_other,
so the base filesystem can be launched on a disposable fixture.

## Results available now

`results/read_cost.png` and `results/read_throughput.png` contain measured
microbenchmark results from the actual Go callbacks, repeated five times for
4 KiB, 64 KiB and 1 MiB reads with one/four workers. Raw samples are in
`results/microbench.txt` and `results/microbench.csv`; machine/build details are
in `results/environment.json`.

**These are not eBPF speedup measurements.** The local sandbox has no `/dev/fuse`
and no effective/bounding capabilities. The compiled BPF loader failed with
`EPERM`, recorded in `results/lsm-self-test.stderr`. No BPF program was attached,
and its verifier/functional tests have not run on this host.

The microbenchmark compares:

1. The repository's real `RenameFile.Read`: verdict-file polling, mutex, CSV
   formatting and actual file logging, then `ReadResult.Bytes` to perform a read.
2. Its embedded `LoopbackFile.Read` plus the same data read, with detector work
   absent. This is an unprotected control, not an implemented protection backend.
3. Direct `syscall.Pread`, also an unprotected control.

All use an 8 MiB warm file and the buffered Pread fallback. They exclude FUSE
request transport, splice, kernel page-cache hits in an actual FUSE mount, model
inference, log rotation and the malicious response branch. Read content is checked
by `TestReadBenchmarkControls`. Parallel `ns/op` is amortized wall time per
operation (inverse aggregate throughput), not individual request latency.

Single-worker medians from this run:

| Read size | Base callback | Plain loopback control | Ratio (base/control) |
| --- | ---: | ---: | ---: |
| 4 KiB | 5.667 us | 0.4463 us | 12.70 |
| 64 KiB | 14.135 us | 4.140 us | 3.41 |
| 1 MiB | 111.480 us | 94.591 us | 1.18 |

These ratios quantify overhead that disappears when protection work is removed;
they do not predict the cost of replacing that work with BPF. High reported
throughput reflects memory/page-cache reads, not physical disk throughput.

## Actual eBPF read backend

`read_lsm.bpf.c` implements `lsm/file_permission`, following the BpfShield pattern:
preserve previous LSM denial, match process TGID and file device/inode, consult
the verdict map, count allowed/denied checks, return `-EACCES` for denied reads.
The kernel serves native file data; Go FUSE is bypassed by the native test path.

The loader holds the fixture open (preventing inode reuse), attaches before
releasing the workload process, and destroys the link/maps afterward. Its scope
is that one file and live process. No global maps/policies are overwritten or
pinned. Threads share TGID; child processes are outside this experiment's scope.
Counters measure permission checks, not general completed-read features. This
prototype does not implement mmap revocation, write enforcement, recursive path
scope, per-window classifier features, or transparent FUSE passthrough.

`--self-test` checks allow, deny on an already-open descriptor, unrelated file,
unrelated process, re-allow, and map counters. `--verdict FILE` optionally mirrors
the base detector's `true`/`false` file every 10 ms. Invalid/unreadable verdicts
abort the workload. The base classifier truncates then writes that file; use
atomic replacement for this optional prototype bridge. Benchmark runs use a
constant allow verdict, with no classifier or rename worker.

Native eBPF reads are a separate backend prototype. The base mount still uses
its original callbacks; no option silently strips protection from that mount.

## Run the real three-way comparison

On a Linux host/VM with `/dev/fuse`, active BPF LSM, BTF and suitable privileges:

```bash
sudo bash benchmark/read-path/run_host.sh
```

Dependencies: Go >=1.16 (tested here with 1.23), clang with BPF target, bpftool,
libbpf development headers, pkg-config, make, a C compiler, fusermount/fusermount3,
Python 3 with matplotlib and numpy. Building the original Go module may need
network access to fetch its dependencies.

The script builds both backends, creates a disposable 64 MiB benign file, checks
LSM denial, mounts the existing filesystem with a constant benign verdict, and
compares native, native+LSM and base FUSE. It then unmounts and removes the fixture.
Results go to a new `results/live-TIMESTAMP/` directory. No malware is run.
No kernel upgrade is required for this native+LSM experiment; it does not use
FUSE passthrough. The CPU/Go/toolchain/dependency versions should be recorded on
the deployment host when comparing across machines.

The live runner randomizes mode order with a fixed seed, warms each file, runs
five repetitions at 1/4 workers and 4/64/1024 KiB, and records throughput plus
sampled p50/p95/p99 read latency. The benchmark starts the base FUSE mount with
-direct-io, which returns FOPEN_DIRECT_IO from Open so timed reads reach the
userspace daemon instead of being served from the FUSE page cache. This is
benchmark-only; normal mounts keep their default cached behavior. The backing
file remains warm in the host page cache, isolating FUSE request and callback
overhead from storage latency.
Baseline log rotation runs normally; the model is held benign to isolate reads.

The runner refuses to label a plain native path as FUSE, verifies fixture contents,
requires the LSM self-test, and requires observed BPF counters for every measured
LSM run. If attachment fails it produces an error log, not a fabricated eBPF bar.

To benchmark an existing fixture/mount yourself:

```bash
make -C benchmark/read-path
go build -o benchmark/read-path/build/native-read benchmark/read-path/native/main.go
sudo python3 benchmark/read-path/run_compare.py \
  --file /path/to/backing/sample.txt --fuse-file /path/to/mount/sample.txt
```

Omit `--fuse-file` for native versus native+LSM only. The fixture must be an
existing nonempty regular file of at least 1 MiB; it is never modified by the
read workload. Live records and their attachment checks are separate from the
callback microbenchmarks.

## Reproduce the callback plots

From the repository root, with the original Go dependencies available:

```bash
go test -vet=off ./MA_custom_filesystems/rename_fs \
  -run '^TestReadBenchmarkControls$' -bench '^BenchmarkReadPath$' \
  -benchtime=200ms -count=5 -cpu=1,4 > benchmark/read-path/results/microbench.txt
MPLCONFIGDIR=/tmp/fs-mtd-matplotlib python3 benchmark/read-path/plot_microbench.py \
  benchmark/read-path/results/microbench.txt --out benchmark/read-path/results
```

`-vet=off` avoids an existing int-to-string warning in the original entropy code.
The local recorded run used an offline temporary GOPATH, the unchanged callback
source and cached `golang.org/x/sys@v0.31.0` rather than modifying `go.mod`.
The exact command and dependency deviation are recorded in `environment.json`.

References: [BPF LSM](https://docs.kernel.org/bpf/prog_lsm.html),
local `/home/sambhav/BpfShield/enforce.bpf.c` and `loader.c`.
