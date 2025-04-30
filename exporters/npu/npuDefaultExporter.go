//go:build !npu
// +build !npu

package npu

import (
	"net/http"

	"github.com/professorshandian/npu-exporter/server"
)

func RegisterNpuService(server *http.Server, npuConfigInfo *server.NpuConfig) {
}
