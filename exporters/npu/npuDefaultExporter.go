//go:build !npu
// +build !npu

package npu

import (
	"net/http"
)

func RegisterNpuService(server *http.Server) {
}
