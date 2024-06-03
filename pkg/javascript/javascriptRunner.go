package javascript

import (
	"github.com/dop251/goja"
	"go.uber.org/zap"
)

type JSRunner struct {
	runtime *goja.Runtime
}

type ExportsMock struct {
}

func NewJSRunner(logger *zap.Logger) *JSRunner {
	vm := goja.New()
	vm.Set("exports", ExportsMock{})
	return &JSRunner{
		runtime: vm,
	}
}

func (runner *JSRunner) runCode(str string) (goja.Value, error) {
	return runner.runtime.RunString(str)
}

func (runner *JSRunner) runFunction(name string, args ...interface{}) (goja.Value, error) {
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
