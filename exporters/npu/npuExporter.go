//go:build npu
// +build npu

package npu

// /*
// #cgo LDFLAGS: -L. -lnpumonitor
// #include "libnpumonitor.h"

// void NpuServer();
// */
// import "C"

func RegisterNpuService() {
	//C.NpuServer()
}
