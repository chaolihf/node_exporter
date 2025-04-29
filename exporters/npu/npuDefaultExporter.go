//go:build !npu
// +build !npu

package npu

import (
	"net/http"
)

type NpuConfig struct {
	NpuListenIp   string
	NpuLogFile    string
	NpuLogLevel   int
	NpuMaxBackups int
	NpuMaxAge     int
}

func RegisterNpuService(server *http.Server, npuConfigInfo *NpuConfig) {
}
