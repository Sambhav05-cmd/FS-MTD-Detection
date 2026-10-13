#ifndef FS_MTD_READ_COMMON_H
#define FS_MTD_READ_COMMON_H
struct read_config {
    __u64 inode;
    __u32 tgid;
    __u32 dev_major;
    __u32 dev_minor;
    __u32 deny;
};
struct read_counts {
    __u64 allowed;
    __u64 denied;
};
#endif
