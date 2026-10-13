#!/usr/bin/env python3
"""Live native vs native+LSM, with optional existing FUSE mount comparison.

Fails before benchmarking if LSM self-test cannot run. Does not mount filesystems,
change the fixture, create a VM, or execute any ransomware.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import platform

HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument("--file", type=Path, required=True, help="native backing fixture, at least 1 MiB")
p.add_argument("--fuse-file", type=Path, help="same fixture through an already-mounted base filesystem")
p.add_argument("--output", type=Path, default=HERE/"results/live")
p.add_argument("--repeats", type=int, default=5)
p.add_argument("--duration", default="500ms")
args = p.parse_args()
args.file = args.file.resolve()
if args.repeats < 1 or args.file.stat().st_size < 1048576:
    p.error("use a fixture >=1 MiB and positive repeats")
if args.fuse_file:
    args.fuse_file = args.fuse_file.resolve()
    # Prevent a typo from labelling another native path as a FUSE measurement.
    matches = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        mount = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1],8)), before.split()[4])
        if args.fuse_file == Path(mount) or Path(mount) in args.fuse_file.parents:
            matches.append((len(mount), after.split()[0]))
    if not matches or not max(matches)[1].startswith("fuse"):
        p.error("--fuse-file must actually reside on a FUSE mount")
    def digest(path):
        h = hashlib.sha256()
        with path.open("rb") as f:
            for block in iter(lambda: f.read(1<<20), b""): h.update(block)
        return h.digest()
    if digest(args.file) != digest(args.fuse_file): p.error("native/FUSE fixture contents differ")
args.output.mkdir(parents=True, exist_ok=True)
loader, obj, reader = (HERE/"build"/x for x in ("read-lsm","read_lsm.bpf.o","native-read"))
for path in (loader,obj,reader):
    if not path.exists(): p.error(f"Missing {path}; run make and build native/main.go first")
metadata = dict(kernel=platform.release(),machine=platform.machine(),file=str(args.file),
                file_bytes=args.file.stat().st_size,fuse_file=str(args.fuse_file) if args.fuse_file else None,
                cache="warm fixture/backing pages; base_fuse uses FOPEN_DIRECT_IO",repeats=args.repeats,duration=args.duration,
                ebpf_measured=False,scope="one file and one live workload process; permission-check counters")
(args.output/"environment.json").write_text(json.dumps(metadata,indent=2)+"\n")
selftest = subprocess.run([str(loader),"--self-test",str(obj),str(args.file)],capture_output=True,text=True)
(args.output/"lsm-self-test.log").write_text(selftest.stdout+selftest.stderr)
if selftest.returncode:
    sys.exit("LSM self-test failed. No live comparison produced; see lsm-self-test.log")
modes = ["native", "native_lsm"] + (["base_fuse"] if args.fuse_file else [])
jobs = [(size,w,r,mode) for size in (4096,65536,1048576) for w in (1,4) for r in range(args.repeats) for mode in modes]
random.Random(42).shuffle(jobs)
rows=[]
for i,(size,workers,repeat,mode) in enumerate(jobs):
    path = args.fuse_file if mode=="base_fuse" else args.file
    command = [str(reader),"-file",str(path),"-block",str(size),"-workers",str(workers),"-duration",args.duration,"-mode",mode]
    if mode=="native_lsm": command=[str(loader),str(obj),str(args.file),"--"]+command
    run=subprocess.run(command,capture_output=True,text=True)
    (args.output/f"run-{i:03d}.stderr").write_text(run.stderr)
    if run.returncode: sys.exit(f"Measurement failed ({mode}); partial rows are in raw.jsonl")
    row=json.loads(run.stdout)
    if mode=="native_lsm":
        match=re.search(r"LSM_COUNTS allowed=(\d+) denied=(\d+)",run.stderr)
        if not match or int(match[1])<row["operations"] or int(match[2])!=0:
            sys.exit("Missing/incorrect LSM accounting; reject this measurement")
        row["lsm_allowed_checks"],row["lsm_denied_checks"]=int(match[1]),int(match[2])
    row["repeat"]=repeat
    rows.append(row)
    with (args.output/"raw.jsonl").open("w") as f:
        for value in rows: f.write(json.dumps(value)+"\n")
    print(f"[{i+1}/{len(jobs)}] {mode} {size//1024} KiB / {workers} workers: {row['mib_per_sec']:.1f} MiB/s",flush=True)
metadata["ebpf_measured"]=True
(args.output/"environment.json").write_text(json.dumps(metadata,indent=2)+"\n")
os.environ.setdefault("MPLCONFIGDIR","/tmp/fs-mtd-matplotlib")
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
for metric,title,ylabel in [("mib_per_sec","Live read throughput","MiB/s"),("sampled_p95_us","Sampled per-read p95 latency","Microseconds")]:
    fig,axes=plt.subplots(1,2,figsize=(12,5))
    for ax,w in zip(axes,(1,4)):
        for mode in modes:
            groups=[[r[metric] for r in rows if r['mode']==mode and r['workers']==w and r['block_bytes']==size] for size in (4096,65536,1048576)]
            mid=np.array([np.median(g) for g in groups])
            ax.errorbar([0,1,2],mid,yerr=[[m-min(g) for m,g in zip(mid,groups)],[max(g)-m for m,g in zip(mid,groups)]],marker="o",capsize=4,label=mode)
        ax.set_xticks([0,1,2],["4 KiB","64 KiB","1024 KiB"])
        ax.set_title(f"{w} worker(s)")
        ax.set_ylabel(ylabel)
        ax.set_xlabel("Read size")
        ax.grid(alpha=.2)
        ax.legend()
    fig.suptitle(title+" — measured LSM attached")
    fig.text(.5,.01,"Warm backing-file cache; FUSE direct I/O; median across repeats; whiskers = min/max.",ha="center",fontsize=9)
    fig.tight_layout(rect=(0,.06,1,.94))
    for ext in ("png","svg"): fig.savefig(args.output/f"{metric}.{ext}",dpi=170)
    plt.close(fig)
