//go:build npu
// +build npu

package npu

// /*
// #cgo LDFLAGS: -L. -lnpumonitor
// #include "libnpumonitor.h"

// void NpuServer();
// */
// import "C"

import (
	"net/http"

	"github.com/chaolihf/node_exporter/mind-cluster/component/npu-exporter/cmd"
)

func RegisterNpuService(server *http.Server, npuConfigInfo *NpuConfig) {
	// C.NpuServer()
	cmd.NpuServer(server, npuConfigInfo)
}
