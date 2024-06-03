package javascript

import (
	"github.com/chaolihf/udpgo/lang"
	"github.com/dop251/goja"
	"go.uber.org/zap"
)

type JSRunner struct {
	runtime *goja.Runtime
}

type ExportsMock struct {
}

var logger *zap.Logger

func init() {
	logger = lang.InitProductLogger("javascriptRunner.log", 300, 3, 10)
}
func NewJSRunner() *JSRunner {
	vm := goja.New()
	vm.Set("exports", ExportsMock{})
	return &JSRunner{
		runtime: vm,
	}
}

func (runner *JSRunner) RunCode(str string) (goja.Value, error) {
	return runner.runtime.RunString(str)
}

func (runner *JSRunner) RunFunction(name string, args ...interface{}) (goja.Value, error) {
	function, ok := goja.AssertFunction(runner.runtime.Get(name))
	var values []goja.Value
	for _, v := range args {
		values = append(values, runner.runtime.ToValue(v))
	}
	if ok {
		return function(goja.Undefined(), values...)
	} else {
		return nil, &goja.InterruptedError{}
	}
}
