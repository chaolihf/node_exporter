package javascript

import (
	"fmt"
	"log"
	"os"
	"testing"
)

func TestJavaScript_RunFunction(t *testing.T) {
	data, err := os.ReadFile("test/arpParse.js")
	if err != nil {
		log.Fatal(err)
	}
	source := string(data)
	runner := NewJSRunner()
	_, err = runner.RunCode(source)
	if err != nil {
		panic(err)
	}
	fmt.Println("start run test")
	data, err = os.ReadFile("test/huawei-arp.txt")
	if err != nil {
		log.Fatal(err)
	}
	content := string(data)
	v, err := runner.RunFunction("getArpInfo", content)
	if err != nil {
		log.Fatal(err)
	}
	arpInfo := v.Export()
	fmt.Println(arpInfo)
}
