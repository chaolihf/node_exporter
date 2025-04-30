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

	"github.com/professorshandian/npu-exporter/server"
)

func RegisterNpuService(server *http.Server, npuConfigInfo *server.NpuConfig) {
	// C.NpuServer()
	server.NpuSer ver(server, npuConfigInfo)
}
