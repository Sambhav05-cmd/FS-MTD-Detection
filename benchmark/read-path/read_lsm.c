#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "read_common.h"

static volatile sig_atomic_t stopped;
static void on_signal(int sig) { stopped = sig; }

static int publish(int fd, struct read_config *cfg)
{
    __u32 key = 0;
    return bpf_map_update_elem(fd, &key, cfg, BPF_ANY);
}

static int verdict(const char *path)
{
    FILE *f = fopen(path, "r");
    char word[16] = {0};
    if (!f) return -1;
    int n = fscanf(f, "%15s", word);
    fclose(f);
    if (n != 1) return -1;
    if (!strcmp(word, "true")) return 1;
    if (!strcmp(word, "false")) return 0;
    return -1;
}

int main(int argc, char **argv)
{
    bool selftest = false;
    const char *verdict_path = NULL;
    int arg = 1;
    if (arg < argc && !strcmp(argv[arg], "--self-test")) { selftest = true; arg++; }
    if (arg + 1 < argc && !strcmp(argv[arg], "--verdict")) { verdict_path = argv[arg+1]; arg += 2; }
    if (argc - arg < 2 || (!selftest && (argc - arg < 4 || strcmp(argv[arg+2], "--")))) {
        fprintf(stderr, "Usage: %s [--verdict FILE] OBJECT FIXTURE -- COMMAND [ARGS...]\n"
                        "       %s --self-test OBJECT FIXTURE\n", argv[0], argv[0]);
        return 2;
    }
    const char *object_path = argv[arg], *fixture_path = argv[arg+1];
    int rc = 1, fixture = -1, config_fd = -1, pipefd[2] = {-1,-1};
    pid_t child = -1;
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;
    struct read_counts *percpu = NULL;
    struct stat st;
    struct read_config cfg = {0};
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    // Older kernels charge BPF objects against memlock. Failure is allowed to
    // reach the actual loader so its permission/error diagnostics are retained.
    struct rlimit lim = {RLIM_INFINITY, RLIM_INFINITY};
    (void)setrlimit(RLIMIT_MEMLOCK, &lim);
    fixture = open(fixture_path, O_RDONLY | O_CLOEXEC);
    if (fixture < 0 || fstat(fixture, &st) || !S_ISREG(st.st_mode) || st.st_size == 0) {
        fprintf(stderr, "Fixture must be a nonempty regular file: %s\n", fixture_path);
        goto done;
    }
    cfg.inode = st.st_ino;
    cfg.dev_major = major(st.st_dev);
    cfg.dev_minor = minor(st.st_dev);
    cfg.tgid = getpid();
    if (verdict_path) {
        int v = verdict(verdict_path);
        if (v < 0) { fprintf(stderr, "Invalid verdict file\n"); goto done; }
        cfg.deny = v;
    }
    obj = bpf_object__open_file(object_path, NULL);
    if (!obj || libbpf_get_error(obj)) { obj = NULL; fprintf(stderr, "Cannot open BPF object\n"); goto done; }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "BPF LOAD FAILED: no eBPF measurement was taken. Check capabilities, BPF LSM and verifier output.\n");
        goto done;
    }
    config_fd = bpf_object__find_map_fd_by_name(obj, "read_cfg");
    int counts_fd = bpf_object__find_map_fd_by_name(obj, "counts");
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "check_read");
    if (config_fd < 0 || counts_fd < 0 || !prog) goto done;
    if (!selftest) {
        if (pipe2(pipefd, O_CLOEXEC)) goto done;
        child = fork();
        if (child < 0) goto done;
        if (!child) {
            char go;
            close(pipefd[1]);
            if (read(pipefd[0], &go, 1) != 1) _exit(125);
            close(pipefd[0]);
            execvp(argv[arg+3], &argv[arg+3]);
            perror("execvp");
            _exit(126);
        }
        close(pipefd[0]); pipefd[0] = -1;
        cfg.tgid = child;
    }
    if (publish(config_fd, &cfg)) goto done;
    link = bpf_program__attach_lsm(prog);
    if (!link || libbpf_get_error(link)) { link = NULL; fprintf(stderr, "LSM ATTACH FAILED; measurement aborted\n"); goto done; }
    if (selftest) {
        char data;
        cfg.deny = 0;
        if (publish(config_fd, &cfg) || pread(fixture, &data, 1, 0) != 1) goto done;
        cfg.deny = 1;
        if (publish(config_fd, &cfg)) goto done;
        errno = 0;
        if (pread(fixture, &data, 1, 0) != -1 || errno != EACCES) {
            fprintf(stderr, "FAIL: existing descriptor was not denied\n"); goto done;
        }
        // Different inode remains readable even while this fixture is denied.
        FILE *other = tmpfile();
        if (!other) goto done;
        if (fwrite("x", 1, 1, other) != 1 || fflush(other) || pread(fileno(other), &data, 1, 0) != 1) {
            fclose(other); goto done;
        }
        fclose(other);
        // Same fixture in another process remains outside this prototype scope.
        pid_t other_pid = fork();
        if (other_pid < 0) goto done;
        if (!other_pid) _exit(pread(fixture, &data, 1, 0) == 1 ? 0 : 1);
        int status;
        if (waitpid(other_pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status)) goto done;
        cfg.deny = 0;
        if (publish(config_fd, &cfg) || pread(fixture, &data, 1, 0) != 1) goto done;
        fprintf(stderr, "PASS: allow, deny existing descriptor, unrelated inode/process, re-allow\n");
    } else {
        if (write(pipefd[1], "x", 1) != 1) goto done;
        close(pipefd[1]); pipefd[1] = -1;
        int status = 0;
        while (!stopped) {
            pid_t done_pid = waitpid(child, &status, WNOHANG);
            if (done_pid == child) { child = -1; break; }
            if (done_pid < 0) { if (errno == EINTR) continue; goto done; }
            if (verdict_path) {
                int v = verdict(verdict_path);
                if (v < 0) { fprintf(stderr, "Verdict unavailable/invalid; aborting workload\n"); goto done; }
                if ((__u32)v != cfg.deny) {
                    cfg.deny = v;
                    if (publish(config_fd, &cfg)) goto done;
                }
            }
            struct timespec pause = {.tv_nsec = 10000000};
            nanosleep(&pause, NULL);
        }
        if (stopped || !WIFEXITED(status) || WEXITSTATUS(status)) goto done;
    }
    int cpus = libbpf_num_possible_cpus();
    if (cpus <= 0) goto done;
    percpu = calloc(cpus, sizeof(*percpu));
    __u32 key = 0;
    if (!percpu || bpf_map_lookup_elem(counts_fd, &key, percpu)) goto done;
    unsigned long long allowed = 0, denied = 0;
    for (int i = 0; i < cpus; i++) { allowed += percpu[i].allowed; denied += percpu[i].denied; }
    fprintf(stderr, "LSM_COUNTS allowed=%llu denied=%llu\n", allowed, denied);
    if (!allowed || (selftest && denied != 1)) {
        fprintf(stderr, "FAIL: expected LSM counters missing; reject timing results\n"); goto done;
    }
    rc = 0;
done:
    if (child > 0) { kill(child, SIGKILL); while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {} }
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    free(percpu);
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    if (fixture >= 0) close(fixture);
    return rc;
}
