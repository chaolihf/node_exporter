package javascript

import (
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/chaolihf/udpgo/lang"
)

func TestJavaScript_RunFunction(t *testing.T) {
	data, err := os.ReadFile("../../exporters/script/test/arpParse.js")
	if err != nil {
		log.Fatal(err)
	}
	source := string(data)
	logger := lang.InitProductLogger("javascriptRunner.log", 300, 3, 10)
	runner := NewJSRunner(logger)
	_, err = runner.runCode(source)
	if err != nil {
		panic(err)
	}
	fmt.Println("start run test")
	data, err = os.ReadFile("../../exporters/script/test/huawei-arp.txt")
	if err != nil {
		log.Fatal(err)
	}
	content := string(data)
	v, err := runner.runFunction("getArpInfo", content)
	arpInfo := v.Export()
	fmt.Println(arpInfo)
}
