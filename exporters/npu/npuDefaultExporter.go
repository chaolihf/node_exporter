//go:build !npu
// +build !npu

package npu

import (
	"net/http"

	"github.com/go-kit/log"
)

func SetLogger(globalLogger log.Logger) {
}
func RequestHandler(w http.ResponseWriter, r *http.Request) {
}
