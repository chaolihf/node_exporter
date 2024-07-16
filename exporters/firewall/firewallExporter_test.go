package firewall

import (
	"os"
	"testing"

	"github.com/chaolihf/node_exporter/pkg/javascript"
	"github.com/chaolihf/node_exporter/pkg/utils"
)

func TestHuaweiFormat(t *testing.T) {
	metricInfo, err := utils.ReadStringFromFile("test/firewallMetrics.json")
	if err != nil {
		t.Error(err)
	}
	FormatConfigInfo(metricInfo)
}

func TestH3Format(t *testing.T) {
	metricInfo, err := utils.ReadStringFromFile("test/firewallMetricsForH3.json")
	if err != nil {
		t.Error(err)
	}
	FormatConfigInfo(metricInfo)
}

func TestGenerateH3Format(t *testing.T) {
	scriptCode, err := utils.ReadStringFromFile("manufacturer/firewall-h3.js")
	if err != nil {
		t.Fatal(err.Error())
	}
	runner := javascript.NewJSRunner()
	_, err = runner.RunCode(scriptCode)
	if err != nil {
		t.Fatal(err.Error())
	}
	content, err := utils.ReadStringFromFile("test/firewall-h3-configuration.txt")
	if err != nil {
		t.Fatal(err.Error())
	}
	content, err = RunScript(runner, "getConfInfo", content)
	if err != nil {
		t.Fatal(err.Error())
	}
	file, err := os.Create("test/firewallMetricsForH3.json")
	if err != nil {
		t.Fatal(err.Error())
	}
	file.WriteString(content)
	if err != nil {
		t.Fatal(err.Error())
	}
	file.Close()
}

func TestGenerateHuaweiFormat(t *testing.T) {
	scriptCode, err := utils.ReadStringFromFile("manufacturer/firewall-huawei.js")
	if err != nil {
		t.Fatal(err.Error())
	}
	runner := javascript.NewJSRunner()
	_, err = runner.RunCode(scriptCode)
	if err != nil {
		t.Fatal(err.Error())
	}
	content, err := utils.ReadStringFromFile("test/firewall-huawei-configuration.txt")
	if err != nil {
		t.Fatal(err.Error())
	}
	content, err = RunScript(runner, "getConfInfo", content)
	if err != nil {
		t.Fatal(err.Error())
	}
	file, err := os.Create("test/firewallMetricsForHuawei.json")
	if err != nil {
		t.Fatal(err.Error())
	}
	file.WriteString(content)
	if err != nil {
		t.Fatal(err.Error())
	}
	file.Close()
}
