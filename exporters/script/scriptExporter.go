package script

import (
	"encoding/json"
	stdlog "log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/chaolihf/node_exporter/pkg/clients/sshclient"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var logger log.Logger

type scriptCollector struct {
	TargetName string
}

type ShellConfig struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	User     string `json:"user"`
	Password string `json:"password"`
	Mode     string `json:"mode"`
	Command  string `json:"command"`
	Prompt   string `json:"prompt"`
}

type ExporterConfig struct {
	Shells []ShellConfig `json:"scripts"`
}

type Template struct {
	Name         string
	Pattern      string
	LineSperator string
	MoreCommand  string
	ClearLine    string
	StartLine    string
	EndLine      string
	ignoreEcho   bool
	Fields       []string
}

var exporterInfo ExporterConfig

var switchTemplates map[string]Template

var isScriptInited = false

func (collector *scriptCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (collector *scriptCollector) Collect(ch chan<- prometheus.Metric) {
	for _, shellInfo := range exporterInfo.Shells {
		if shellInfo.Name == collector.TargetName {
			var metrics []prometheus.Metric
			switch shellInfo.Mode {
			case "h3":
				metrics = getScriptResult(shellInfo, switchTemplates[shellInfo.Mode])
			case "huawei":
				metrics = getScriptResult(shellInfo, switchTemplates[shellInfo.Mode])
			}
			for _, metric := range metrics {
				ch <- metric
			}
			break
		}
	}

}

func getScriptResult(shellInfo ShellConfig, template Template) []prometheus.Metric {
	session := sshclient.NewSSHSession(shellInfo.Host, shellInfo.User, shellInfo.Password, 10)
	if session == nil {
		return nil
	}
	defer session.CloseSession()
	var content string
	var err error
	if template.Name == "huawei" {
		content, err = session.ExecuteShellCommand(shellInfo.Command,
			template.MoreCommand, shellInfo.Prompt, template.ClearLine)
	} else {
		content, err = session.ExecuteSingleCommand(shellInfo.Command, template.StartLine)
	}
	if err != nil {
		return nil
	}
	file, _ := os.Create("temp.txt")
	file.WriteString(content)
	file.Close()
	tableInfo := ParseTableData(content, template.LineSperator, template.Pattern)
	metrics := CreateMetrics(tableInfo, template.Fields)
	session.SendShellCommand("display ospf peer brief")
	content = session.GetShellCommandResult(
		shellInfo.Prompt, template.MoreCommand, template.ClearLine)
	file, _ = os.Create("temp.txt")
	file.WriteString(content)
	file.Close()
	return metrics
}

func CreateMetrics(tableInfo [][]string, columnNames []string) []prometheus.Metric {
	var metrics []prometheus.Metric
	for _, row := range tableInfo {
		var tags = make(map[string]string)
		for i := 0; i < len(columnNames); i++ {
			if len(row) > i {
				tags[columnNames[i]] = strings.Trim(row[i], " ")
			} else {
				tags[columnNames[i]] = ""
			}
		}
		scriptMetric := prometheus.NewDesc("arp_addresss", "", nil, tags)
		metric := prometheus.MustNewConstMetric(scriptMetric, prometheus.CounterValue, 1)
		metrics = append(metrics, metric)
	}
	return metrics
}
func ParseTableData(content string, lineSperator string, rowPattern string) [][]string {
	var table [][]string
	rows := strings.Split(content, lineSperator)
	regex := regexp.MustCompile(rowPattern)
	var lastIndex = -1
	for _, row := range rows {
		row := strings.Trim(row, " ")
		if len(row) == 0 {
			continue
		}
		matches := regex.FindStringSubmatch(row)
		if len(matches) > 0 {
			table = append(table, matches[1:])
			lastIndex = lastIndex + 1
		} else {
			table[lastIndex] = append(table[lastIndex], row)

		}
	}
	return table
}

func init() {
	filePath := "scriptConfig.json"
	content, err := os.ReadFile(filePath)
	if err != nil {
		stdlog.Printf("读取文件出错:%s,%s", filePath, err.Error())
	} else {
		err := json.Unmarshal(content, &exporterInfo)
		if err != nil {
			stdlog.Printf("解析文件出错:%s", filePath+err.Error())
		}
	}
	switchTemplates = make(map[string]Template)
	switchTemplates["huawei"] = Template{ignoreEcho: false, Name: "huawei", Pattern: `(.{16})(.{16})(.{10})(.{12})(.{15})(.*)`,
		LineSperator: "\r\n", MoreCommand: "---- More ----",
		ClearLine: "\x1B[42D",
		StartLine: "------------------------------------------------------------------------------\r\n",
		EndLine:   "------------------------------------------------------------------------------\r\n",
		Fields:    []string{"ip", "mac", "expire", "type", "interface", "instance", "vlan"},
	}
	switchTemplates["h3"] = Template{
		ignoreEcho: true, Name: "h3", Pattern: `(.{16})(.{15})(.{11})(.{25})(.{6})(.*)`,
		LineSperator: "\r\r\n",
		StartLine:    "Aging Type \r\r\n",
		Fields:       []string{"ip", "mac", "vlan", "interface", "expire", "type", "instance"},
	}

}

func SetLogger(g_logger log.Logger) {
	if !isScriptInited {
		logger = g_logger
		isScriptInited = true
	}
}
func RequestHandler(w http.ResponseWriter, r *http.Request) {
	registry := prometheus.NewRegistry()
	params := r.URL.Query()
	targetName := params.Get("target")
	if targetName == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing target parameter!"))
		return
	}
	registry.MustRegister(&scriptCollector{TargetName: targetName})
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}
