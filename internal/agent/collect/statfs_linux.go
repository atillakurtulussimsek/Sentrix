//go:build linux

package collect

import "syscall"

func platformStatfs(path string) (FSStat, error) {
	var s syscall.Statfs_t
	if err := syscall.Statfs(path, &s); err != nil {
		return FSStat{}, err
	}
	bs := uint64(s.Bsize) //nolint:gosec // block size is positive
	return FSStat{Total: s.Blocks * bs, Free: s.Bfree * bs, Avail: s.Bavail * bs, Inodes: s.Files, InodesFree: s.Ffree}, nil
}
