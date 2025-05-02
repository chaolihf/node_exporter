//go:build npu
// +build npu

package npu

import (
	"net/http"

	npu_exporter "github.com/chaolihf/mind-cluster/component/npu-exporter/cmd/npu-exporter"
)

func RegisterNpuService(server *http.Server) {
	npu_exporter.NpuServer(server)
}
