#!/usr/bin/env python3
"""Plot measured callback controls. Never present them as measured eBPF."""
import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument("input", type=Path)
parser.add_argument("--out", type=Path, default=Path("results"))
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
pattern = re.compile(r"^BenchmarkReadPath/(\d+)/(\w+?)(?:-(\d+))?\s+(\d+)\s+([\d.]+) ns/op\s+([\d.]+) MB/s\s+(\d+) B/op\s+(\d+) allocs/op")
rows = []
for line in args.input.read_text().splitlines():
    m = pattern.match(line)
    if m:
        size, mode, workers, count, ns, mb, allocated, allocs = m.groups()
        rows.append(dict(block_bytes=int(size), mode=mode, workers=int(workers or 1), iterations=int(count),
                         ns_per_op=float(ns), mib_per_sec=int(size)*1e9/float(ns)/(1<<20),
                         bytes_per_op=int(allocated), allocs_per_op=int(allocs)))
if not rows or "PASS" not in args.input.read_text():
    raise SystemExit("No complete successful benchmark run found")
with (args.out/"microbench.csv").open("w") as f:
    writer = csv.DictWriter(f, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
groups = defaultdict(list)
for row in rows:
    groups[(row["workers"], row["block_bytes"], row["mode"])].append(row)
modes = ["current_callback", "plain_loopback_control", "native_pread_control"]
labels = ["Current read callback", "Loopback control (no detector)", "Native pread control (no detector)"]
colors = ["#d95f46", "#4279b7", "#6e9e66"]
sizes = sorted({row["block_bytes"] for row in rows})
workers = sorted({row["workers"] for row in rows})
summary = []
for (w, size, mode), values in sorted(groups.items()):
    summary.append(dict(workers=w, block_bytes=size, mode=mode, repeats=len(values),
                        median_ns_per_op=float(np.median([v["ns_per_op"] for v in values])),
                        median_mib_per_sec=float(np.median([v["mib_per_sec"] for v in values]))))
(args.out/"summary.json").write_text(json.dumps({"scope":"Actual Go callbacks + buffered pread; no FUSE mount or BPF attachment", "ebpf_measured":False, "results":summary},indent=2)+"\n")
plt.rcParams.update({"font.size":10, "axes.spines.top":False, "axes.spines.right":False})
for metric, filename, title, ylabel, scale in [
    ("ns_per_op", "read_cost", "Read callback cost", "Amortized wall time (microseconds/op)", .001),
    ("mib_per_sec", "read_throughput", "Read callback throughput", "Throughput (MiB/s)", 1),
]:
    fig, axes = plt.subplots(1, len(workers), figsize=(12,5.5), squeeze=False)
    x = np.arange(len(sizes))
    for ax, w in zip(axes[0], workers):
        for i, (mode, label, color) in enumerate(zip(modes, labels, colors)):
            samples = [[v[metric]*scale for v in groups[(w,size,mode)]] for size in sizes]
            if any(not s for s in samples): raise SystemExit("Missing comparison group")
            mid = np.array([np.median(s) for s in samples])
            error = np.array([[m-min(s) for m,s in zip(mid,samples)], [max(s)-m for m,s in zip(mid,samples)]])
            ax.bar(x+(i-1)*.25, mid, .23, color=color, label=label, yerr=error, capsize=3)
        ax.set_xticks(x, [f"{s//1024} KiB" for s in sizes])
        ax.set_title(f"{w} worker"+("s" if w!=1 else ""))
        ax.set_ylabel(ylabel)
        ax.set_xlabel("Read size")
        if metric == "ns_per_op": ax.set_yscale("log")
        ax.grid(axis="y", alpha=.2)
        ax.set_axisbelow(True)
    fig.suptitle(title+" | eBPF NOT measured", fontsize=17, weight="bold", y=.99)
    handles, names = axes[0][0].get_legend_handles_labels()
    fig.legend(handles,names,loc="upper center",bbox_to_anchor=(.5,.94),ncol=3,frameon=False)
    fig.text(.5,.02,"Warm 8 MiB file; real CSV writes; median of 5 runs, whiskers = min/max.\nCallback microbenchmark only: excludes /dev/fuse transport and splice; controls remove protection.",ha="center",fontsize=9)
    fig.tight_layout(rect=(0,.10,1,.84))
    for ext in ("png","svg"):
        fig.savefig(args.out/f"{filename}.{ext}",dpi=170)
    plt.close(fig)
print(json.dumps(summary,indent=2))
