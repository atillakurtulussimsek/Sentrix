//go:build !linux

package collect

import "errors"

func platformStatfs(string) (FSStat, error) {
	return FSStat{}, errors.New("statfs: unsupported platform")
}
