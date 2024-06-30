package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"os"

	"github.com/chaolihf/node_exporter/pkg/clients/sshclient"
	"github.com/chaolihf/node_exporter/pkg/javascript"
	"github.com/chaolihf/node_exporter/pkg/utils"
	"github.com/chaolihf/udpgo/lang"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
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
	Prompt   string     `json:"prompt"`
	Steps    []StepInfo `json:"steps"`
}

type ExporterConfig struct {
	Firewalls []ShellConfig `json:"firewalls"`
}

var exporterInfo ExporterConfig
var isScriptInited = false
var firewallLogger *zap.Logger

func (collector *firewallCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for _, firewallInfo := range exporterInfo.Firewalls {
		if firewallInfo.Name == collector.TargetName {
			configInfo, err := getFirewallConfig(firewallInfo)
			if err != nil {
				level.Error(logger).Log("err", "get firewall config "+err.Error())
				return
			}
			w.Write([]byte(configInfo))
			break
		}
	}

}

func getFirewallConfig(shellInfo ShellConfig) (string, error) {
	if len(shellInfo.Steps) != 1 {
		return "", errors.New("should be one step")
	}
	scriptCode, err := utils.ReadStringFromFile(fmt.Sprintf("manufacturer/firewall-%s.js", shellInfo.Mode))
	if err != nil {
		return "", err
	}
	runner := javascript.NewJSRunner()
	_, err = runner.RunCode(scriptCode)
	if err != nil {
		return "", err
	}
	moreCommand, clearLine, err := getShellConfig(runner)
	if err != nil {
		return "", err
	}
	connection := sshclient.NewSSHConnection(shellInfo.Host, shellInfo.User, shellInfo.Password, 10)
	if connection == nil {
		return "", err
	}
	defer connection.CloseConnection()
	session := connection.NewSession("gbk")
	defer session.CloseSession()
	content, err := session.ExecuteShellCommand(shellInfo.Steps[0].Command,
		moreCommand, shellInfo.Prompt, clearLine)
	if err != nil {
		return "", err
	}
	firewallLogger.Info(content)
	file, err := os.Create("output.txt")
	if err != nil {
		fmt.Println("Error:", err)
	}
	file.WriteString(content)
	if err != nil {
		fmt.Println("Error:", err)
	}
	file.Close()
	return runScript(runner, shellInfo.Steps[0].ScriptFunction, content)
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

func runScript(runner *javascript.JSRunner, funcName string, parameter string) (string, error) {
	v, err := runner.RunFunction(funcName, parameter)
	if err != nil {
		return "", err
	}
	jsonConfInfos := v.Export().(string)
	return jsonConfInfos, nil
}

func init() {
	firewallLogger = lang.InitProductLogger("logs/firewall.log", 300, 3, 10)
	filePath := "firewallConfig.json"
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
	params := r.URL.Query()
	targetName := params.Get("target")
	if targetName == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing target parameter!"))
		return
	}
	collector := &firewallCollector{TargetName: targetName}
	collector.ServeHTTP(w, r)
}
