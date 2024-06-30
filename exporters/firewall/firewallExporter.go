package firewall

import (
	"encoding/json"
	"fmt"
	stdlog "log"
	"net/http"
	"strings"

	"github.com/chaolihf/node_exporter/pkg/clients/sshclient"
	"github.com/chaolihf/node_exporter/pkg/javascript"
	"github.com/chaolihf/node_exporter/pkg/utils"
	"github.com/chaolihf/udpgo/lang"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var logger log.Logger

type firewallCollector struct {
	TargetName string
}

type StepInfo struct {
	Command        string `json:"command"`
	ScriptFunction string `json:"scriptFunction"`
}

type ShellConfig struct {
	Name     string     `json:"name"`
	Host     string     `json:"host"`
	User     string     `json:"user"`
	Password string     `json:"password"`
	Mode     string     `json:"mode"`
	Shell    string     `json:"shell"`
	Prompt   string     `json:"prompt"`
	Steps    []StepInfo `json:"steps"`
}

type ExporterConfig struct {
	Switchs []ShellConfig `json:"switchs"`
}

var exporterInfo ExporterConfig
var isScriptInited = false
var switchLogger *zap.Logger

func (collector *firewallCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (collector *firewallCollector) Collect(ch chan<- prometheus.Metric) {
	for _, switchInfo := range exporterInfo.Switchs {
		if switchInfo.Name == collector.TargetName {
			metrics := getScriptResult(switchInfo)
			for _, metric := range metrics {
				ch <- metric
			}
			break
		}
	}

}

func getScriptResult(shellInfo ShellConfig) []prometheus.Metric {
	var metrics []prometheus.Metric
	if len(shellInfo.Steps) == 0 {
		level.Warn(logger).Log("warning", "missing command steps")
		return nil
	}
	scriptCode, err := utils.ReadStringFromFile(fmt.Sprintf("manufacturer/firewall-%s.js", shellInfo.Mode))
	if err != nil {
		level.Error(logger).Log("err", "read manufacturer script code "+err.Error())
		return nil
	}
	runner := javascript.NewJSRunner()
	_, err = runner.RunCode(scriptCode)
	if err != nil {
		level.Error(logger).Log("err", "init script code "+err.Error())
		return nil
	}
	moreCommand, clearLine, err := getShellConfig(runner)
	if err != nil {
		return nil
	}
	connection := sshclient.NewSSHConnection(shellInfo.Host, shellInfo.User, shellInfo.Password, 10)
	if connection == nil {
		return nil
	}
	defer connection.CloseConnection()
	if shellInfo.Shell == "1" {
		session := connection.NewSession("")
		defer session.CloseSession()
		content, err := session.ExecuteShellCommand(shellInfo.Steps[0].Command,
			moreCommand, shellInfo.Prompt, clearLine)
		if err != nil {
			return nil
		}
		switchLogger.Info(content)
		metrics = append(metrics, runScript(runner, shellInfo.Steps[0].ScriptFunction, content)...)
		for _, stepInfo := range shellInfo.Steps[1:] {
			session.SendShellCommand(stepInfo.Command)
			content = session.GetShellCommandResult(shellInfo.Prompt, moreCommand, clearLine)
			switchLogger.Info(content)
			metrics = append(metrics, runScript(runner, stepInfo.ScriptFunction, content)...)
		}
	} else {
		for _, stepInfo := range shellInfo.Steps {
			session := connection.NewSession("")
			content, err := session.ExecuteSingleCommand(stepInfo.Command)
			if err != nil {
				return nil
			}
			switchLogger.Info(content)
			metrics = append(metrics, runScript(runner, stepInfo.ScriptFunction, content)...)
			session.CloseSession()
		}

	}
	return metrics
}

func getShellConfig(runner *javascript.JSRunner) (string, string, error) {
	v, err := runner.RunFunction("getShellConfig")
	if err != nil {
		return "", "", err
	} else {
		shellConfigInfo := v.Export().([]interface{})
		return shellConfigInfo[0].(string), shellConfigInfo[1].(string), nil
	}
}

func runScript(runner *javascript.JSRunner, funcName string, parameter string) []prometheus.Metric {
	v, err := runner.RunFunction(funcName, parameter)
	if err != nil {
		return nil
	}
	metricInfos := v.Export().([]interface{})
	metricName := metricInfos[0].(string)
	var columnNames []string
	for _, columnName := range metricInfos[1].([]interface{}) {
		columnNames = append(columnNames, columnName.(string))
	}
	var tableInfo [][]string
	for _, row := range metricInfos[2].([]interface{}) {
		var rowInfo []string
		for _, cell := range row.([]interface{}) {
			rowInfo = append(rowInfo, cell.(string))
		}
		tableInfo = append(tableInfo, rowInfo)
	}
	return CreateMetrics(metricName, tableInfo, columnNames)
}

func CreateMetrics(metricName string, tableInfo [][]string, columnNames []string) []prometheus.Metric {
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
		scriptMetric := prometheus.NewDesc(metricName, "", nil, tags)
		metric := prometheus.MustNewConstMetric(scriptMetric, prometheus.CounterValue, 1)
		metrics = append(metrics, metric)
	}
	return metrics
}

func init() {
	switchLogger = lang.InitProductLogger("logs/switchs.log", 300, 3, 10)
	filePath := "switchConfig.json"
	content, err := utils.ReadDataFromFile(filePath)
	if err != nil {
		stdlog.Printf("读取文件出错:%s,%s", filePath, err.Error())
	} else {
		err := json.Unmarshal(content, &exporterInfo)
		if err != nil {
			stdlog.Printf("解析文件出错:%s", filePath+err.Error())
		}
	}

}

func SetLogger(globalLogger log.Logger) {
	if !isScriptInited {
		logger = globalLogger
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
	registry.MustRegister(&firewallCollector{TargetName: targetName})
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}
