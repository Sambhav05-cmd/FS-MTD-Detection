package main

// These benchmarks call the real repository callbacks, without mounting FUSE.
// plain_loopback is a control with detector work removed, NOT measured eBPF.
import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func readFixture(t testing.TB) (string, []byte, context.Context) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"logs", "rename_fs"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "logs/classifier.log"), []byte("false"), 0600); err != nil {
		t.Fatal(err)
	}
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(filepath.Join(root, "rename_fs")); err != nil {
		t.Fatal(err)
	}
	oldWriter, oldFlags, oldPrefix := log.Writer(), log.Flags(), log.Prefix()
	out, err := os.Create(filepath.Join(root, "logs/reads.csv"))
	if err != nil {
		t.Fatal(err)
	}
	log.SetOutput(out)
	log.SetFlags(0)
	log.SetPrefix("")
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
		log.SetPrefix(oldPrefix)
		out.Close()
		if err := os.Chdir(oldWD); err != nil {
			t.Error(err)
		}
	})
	data := make([]byte, 8<<20)
	for i := range data {
		data[i] = byte(i*17 + i/4096)
	}
	path := filepath.Join(root, "sample.txt")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx := &fuse.Context{Caller: fuse.Caller{Pid: uint32(os.Getpid())}}
	return path, data, ctx
}

func TestReadBenchmarkControls(t *testing.T) {
	path, data, ctx := readFixture(t)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rf := &RenameFile{LoopbackFile: fs.LoopbackFile{Fd: int(f.Fd())}, name: "sample.txt"}
	buf := make([]byte, 4096)
	for _, read := range []func(context.Context, []byte, int64) (fuse.ReadResult, syscall.Errno){rf.Read, rf.LoopbackFile.Read} {
		res, errno := read(ctx, buf, 4096)
		if errno != 0 {
			t.Fatal(errno)
		}
		got, status := res.Bytes(buf)
		res.Done()
		if status != fuse.OK || !bytes.Equal(got, data[4096:8192]) {
			t.Fatal("read contents differ")
		}
	}
}

func BenchmarkReadPath(b *testing.B) {
	path, _, ctx := readFixture(b)
	for _, size := range []int{4096, 65536, 1048576} {
		for _, mode := range []string{"current_callback", "plain_loopback_control", "native_pread_control"} {
			b.Run(fmt.Sprintf("%d/%s", size, mode), func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					// Each worker has a separate handle, matching independent opens.
					f, err := os.Open(path)
					if err != nil {
						b.Error(err)
						return
					}
					defer f.Close()
					rf := &RenameFile{LoopbackFile: fs.LoopbackFile{Fd: int(f.Fd())}, name: "sample.txt"}
					buf := make([]byte, size)
					var off int64
					for pb.Next() {
						if mode == "native_pread_control" {
							n, err := syscall.Pread(int(f.Fd()), buf, off)
							if err != nil || n != size {
								b.Errorf("pread: n=%d err=%v", n, err)
								return
							}
						} else {
							var res fuse.ReadResult
							var errno syscall.Errno
							if mode == "current_callback" {
								res, errno = rf.Read(ctx, buf, off)
							} else {
								res, errno = rf.LoopbackFile.Read(ctx, buf, off)
							}
							if errno != 0 {
								b.Error(errno)
								return
							}
							got, status := res.Bytes(buf) // Actual buffered Pread fallback, not splice.
							res.Done()
							if status != fuse.OK || len(got) != size {
								b.Errorf("read: bytes=%d status=%v", len(got), status)
								return
							}
						}
						off = (off + int64(size)) % (8 << 20)
					}
				})
			})
		}
	}
}
