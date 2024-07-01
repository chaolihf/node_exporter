/*
firewall exporter
*/
package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"time"

	"github.com/chaolihf/node_exporter/pkg/clients/sshclient"
	"github.com/chaolihf/node_exporter/pkg/javascript"
	"github.com/chaolihf/node_exporter/pkg/utils"
	le "github.com/chaolihf/udpgo/com.chinatelecom.oneops.protocol.logger"
	jjson "github.com/chaolihf/udpgo/json"
	"github.com/chaolihf/udpgo/lang"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
)

var logger log.Logger

type firewallCollector struct {
	TargetName string
	Format     string
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

const (
	AddressId_AddressSet int32 = iota
	AddressId_RuleSet_Source
	AddressId_RuleSet_Destination
)

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
			if collector.Format == "json" {
				w.Write([]byte(configInfo))
			} else {
				content, err := FormatConfigInfo(configInfo)
				if err != nil {
					level.Error(logger).Log("err", "format content "+err.Error())
					return
				} else {
					w.Write(content)
				}
			}
			break
		}
	}

}

func FormatConfigInfo(configInfo string) ([]byte, error) {
	jsonConfigInfos, err := jjson.NewJsonObject([]byte(configInfo))
	if err != nil {
		return nil, err
	}
	loggerDatas := &le.LoggerData{}
	loggerDatas.ReceiveTime = time.Now().UnixMilli()
	loggerDatas.Collector = "firewall"
	loggerDatas.MonitorObject = ""
	loggerDatas.MonitorType = ""
	batchId := utils.GetUUID()
	table_addressSet, table_address := convertAddressSetInfo(batchId, jsonConfigInfos.GetJsonArray("addressSet"))

	loggerDatas.TableData = append(loggerDatas.TableData, table_addressSet, table_address)
	return proto.Marshal(loggerDatas)
}

func convertAddressSetInfo(batchId string, addressSet []*jjson.JsonObject) (*le.TableData, *le.TableData) {
	table_addressSet := &le.TableData{
		TableName: "firewall_addressset",
		Columns: []*le.ColumnData{
			&le.ColumnData{ColumnName: "batch_id", ColumnType: 5},
			&le.ColumnData{ColumnName: "addressset_id", ColumnType: 5},
			&le.ColumnData{ColumnName: "name", ColumnType: 5},
			&le.ColumnData{ColumnName: "description", ColumnType: 5},
			&le.ColumnData{ColumnName: "zone", ColumnType: 5},
		},
	}
	table_address := &le.TableData{
		TableName: "firewall_address_detail",
		Columns: []*le.ColumnData{
			&le.ColumnData{ColumnName: "address_id", ColumnType: 5},
			&le.ColumnData{ColumnName: "id_type", ColumnType: 1},
			&le.ColumnData{ColumnName: "address_detail_id", ColumnType: 5},
			&le.ColumnData{ColumnName: "address_type", ColumnType: 1},
			&le.ColumnData{ColumnName: "address", ColumnType: 5},
			&le.ColumnData{ColumnName: "v4", ColumnType: 1},
			&le.ColumnData{ColumnName: "end_address", ColumnType: 5},
			&le.ColumnData{ColumnName: "mask", ColumnType: 1},
			&le.ColumnData{ColumnName: "name", ColumnType: 5},
		},
	}
	if addressSet == nil {
		return table_addressSet, table_address
	}
	for _, addressSetItem := range addressSet {
		addressset_id := utils.GetUUID()
		table_addressSet.Rows = append(table_addressSet.Rows,
			&le.RowValue{
				FieldValue: []*le.FieldValue{
					&le.FieldValue{Data: &le.FieldValue_S{S: batchId}},
					&le.FieldValue{Data: &le.FieldValue_S{S: addressset_id}},
					&le.FieldValue{Data: &le.FieldValue_S{S: addressSetItem.GetString("name")}},
					&le.FieldValue{Data: &le.FieldValue_S{S: addressSetItem.GetString("description")}},
					&le.FieldValue{Data: &le.FieldValue_S{S: addressSetItem.GetString("zone")}},
				},
			},
		)
		for _, addressItem := range addressSetItem.GetJsonArray("address") {
			var address string
			addressType := int32(addressItem.GetInt("type"))
			switch addressType {
			case 2:
				address = fmt.Sprintf("%s/%d", address, addressType)
			case 1:
				address = addressItem.GetString("start")
			default:
				address = addressItem.GetString("address")
			}
			table_address.Rows = append(table_address.Rows,
				&le.RowValue{
					FieldValue: []*le.FieldValue{
						&le.FieldValue{Data: &le.FieldValue_S{S: addressset_id}},
						&le.FieldValue{Data: &le.FieldValue_I{I: AddressId_AddressSet}},
						&le.FieldValue{Data: &le.FieldValue_S{S: utils.GetUUID()}},
						&le.FieldValue{Data: &le.FieldValue_I{I: addressType}},
						&le.FieldValue{Data: &le.FieldValue_S{S: address}},
						&le.FieldValue{Data: &le.FieldValue_I{I: int32(addressItem.GetInt("v4"))}},
						&le.FieldValue{Data: &le.FieldValue_S{S: addressItem.GetString("end")}},
						&le.FieldValue{Data: &le.FieldValue_I{I: int32(addressItem.GetInt("mask"))}},
						&le.FieldValue{Data: &le.FieldValue_S{S: addressItem.GetString("name")}},
					},
				},
			)
		}
	}
	return table_addressSet, table_address
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
	// file, err := os.Create("output.txt")
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }
	// file.WriteString(content)
	// if err != nil {
	// 	fmt.Println("Error:", err)
	// }
	// file.Close()
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
	format := params.Get("format")
	if format == "" {
		format = "table"
	}
	collector := &firewallCollector{TargetName: targetName, Format: format}
	collector.ServeHTTP(w, r)
}
