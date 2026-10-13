#!/usr/bin/env bash
# Run on a Linux host/VM with FUSE, BPF LSM, libbpf, clang, bpftool, Go,
# and Python matplotlib/numpy. Uses only a disposable benign fixture.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
output=${1:-"$here/results/live-$(date +%Y%m%d-%H%M%S)"}
if [[ $EUID -ne 0 ]]; then
    echo "Run this script with sudo on the host/VM (BPF and FUSE privileges required)." >&2
    exit 1
fi
[[ -c /dev/fuse ]] || { echo 'Missing /dev/fuse; cannot run the mounted comparison.' >&2; exit 1; }
grep -qw bpf /sys/kernel/security/lsm || { echo 'BPF LSM is not active.' >&2; exit 1; }
# sudo hides the invoking user's pip --user packages from root's Python.
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root ]]; then
    user_site=$(sudo -H -u "$SUDO_USER" python3 -m site --user-site)
    export PYTHONPATH="$user_site${PYTHONPATH:+:$PYTHONPATH}"
    go_bin=$(sudo -H -u "$SUDO_USER" bash -lc 'command -v go' 2>/dev/null || true)
else
    go_bin=$(command -v go || true)
fi
if [[ -z ${go_bin:-} ]]; then
    for candidate in /usr/local/go/bin/go "/home/${SUDO_USER:-sambhav}/go/bin/go"; do
        if [[ -x $candidate ]]; then go_bin=$candidate; break; fi
    done
fi
[[ -n ${go_bin:-} ]] || { echo "Go was not found; install Go or add it to PATH." >&2; exit 1; }
python3 -c 'import matplotlib, numpy'
make -C "$here"
"$go_bin" build -o "$here/build/native-read" "$here/native/main.go"
(cd "$repo" && "$go_bin" build -o "$here/build/base-fuse" ./MA_custom_filesystems/rename_fs)
work=$(mktemp -d /tmp/fs-mtd-read-XXXXXX)
server_pid=
cleanup() {
    set +e
    if mountpoint -q "$work/mnt"; then
        if command -v fusermount3 >/dev/null; then fusermount3 -u "$work/mnt"; else fusermount -u "$work/mnt"; fi
    fi
    if [[ -n $server_pid ]]; then kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null; fi
    if ! mountpoint -q "$work/mnt"; then rm -rf -- "$work"; else echo "Mount still active: $work/mnt; fixture retained." >&2; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$work/backing" "$work/mnt" "$work/logs" "$work/run"
printf false > "$work/logs/classifier.log"
dd if=/dev/urandom of="$work/backing/sample.txt" bs=1M count=64 status=none
# Validate the BPF backend before starting the baseline mount.
"$here/build/read-lsm" --self-test "$here/build/read_lsm.bpf.o" "$work/backing/sample.txt"
(
    cd "$work/run"
    exec "$here/build/base-fuse" -mount "$work/mnt" -backing "$work/backing" \
        -log-pattern "$work/logs/logfile%d.csv" -allow-other=false -direct-io
) > "$work/fuse.stdout" 2> "$work/fuse.stderr" &
server_pid=$!
for _ in {1..100}; do
    mountpoint -q "$work/mnt" && break
    if ! kill -0 "$server_pid" 2>/dev/null; then cat "$work/fuse.stderr" >&2; exit 1; fi
    sleep .1
done
mountpoint -q "$work/mnt" || { cat "$work/fuse.stderr" >&2; exit 1; }
python3 "$here/run_compare.py" --file "$work/backing/sample.txt" \
    --fuse-file "$work/mnt/sample.txt" --output "$output"
cp "$work/fuse.stdout" "$work/fuse.stderr" "$output/"
echo "Measured native, native+LSM, and base FUSE plots: $output"
