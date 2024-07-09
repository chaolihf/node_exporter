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
	loggerExporter "github.com/chaolihf/udpgo/com.chinatelecom.oneops.protocol.logger"
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
	loggerDatas := &loggerExporter.LoggerData{}
	loggerDatas.ReceiveTime = time.Now().UnixMilli()
	loggerDatas.Collector = "firewall"
	loggerDatas.MonitorObject = ""
	loggerDatas.MonitorType = ""
	batchID := utils.GetUUID()
	tableAddressSet, tableAddress := convertAddressSetInfo(batchID, jsonConfigInfos.GetJsonArray("addressSet"))
	tableServiceSet, tableService := convertServiceSetInfo(batchID, jsonConfigInfos.GetJsonArray("serviceSet"))
	tableDomainSet, tableDomain := convertDomainSetInfo(batchID, jsonConfigInfos.GetJsonArray("domainSet"))
	tableZoneSet, tableZone := convertZoneSetInfo(batchID, jsonConfigInfos.GetJsonArray("zoneSet"))
	tableBlacklist := convertBlacklistInfo(batchID, jsonConfigInfos.GetJsonArray("blacklist"))
	loggerDatas.TableData = append(loggerDatas.TableData, tableAddressSet, tableAddress,
		tableServiceSet, tableService, tableDomainSet, tableDomain, tableZoneSet, tableZone,
		tableBlacklist)
	return proto.Marshal(loggerDatas)
}

func convertBlacklistInfo(batchID string, blacklist []*jjson.JsonObject) *loggerExporter.TableData {
	tableBlacklist := &loggerExporter.TableData{
		TableName: "firewall_blacklist",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "batch_id", ColumnType: 5},
			{ColumnName: "blacklist_id", ColumnType: 5},
			{ColumnName: "name", ColumnType: 5},
		},
	}
	if blacklist == nil {
		return tableBlacklist
	}
	for _, blacklistItem := range blacklist {
		tableBlacklist.Rows = append(tableBlacklist.Rows,
			&loggerExporter.RowValue{
				FieldValue: []*loggerExporter.FieldValue{
					{Data: &loggerExporter.FieldValue_S{S: batchID}},
					{Data: &loggerExporter.FieldValue_S{S: utils.GetUUID()}},
					{Data: &loggerExporter.FieldValue_S{S: blacklistItem.GetString("name")}},
				},
			},
		)
	}
	return tableBlacklist
}

func convertAddressSetInfo(batchID string, addressSet []*jjson.JsonObject) (*loggerExporter.TableData, *loggerExporter.TableData) {
	tableAddressSet := &loggerExporter.TableData{
		TableName: "firewall_addressset",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "batch_id", ColumnType: 5},
			{ColumnName: "addressset_id", ColumnType: 5},
			{ColumnName: "name", ColumnType: 5},
			{ColumnName: "description", ColumnType: 5},
			{ColumnName: "zone", ColumnType: 5},
		},
	}
	tableAddress := &loggerExporter.TableData{
		TableName: "firewall_address_detail",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "address_id", ColumnType: 5},
			{ColumnName: "id_type", ColumnType: 1},
			{ColumnName: "address_detail_id", ColumnType: 5},
			{ColumnName: "address_type", ColumnType: 1},
			{ColumnName: "address", ColumnType: 5},
			{ColumnName: "v4", ColumnType: 1},
			{ColumnName: "end_address", ColumnType: 5},
			{ColumnName: "mask", ColumnType: 1},
			{ColumnName: "name", ColumnType: 5},
		},
	}
	if addressSet == nil {
		return tableAddressSet, tableAddress
	}
	for _, addressSetItem := range addressSet {
		addresSsetID := utils.GetUUID()
		tableAddressSet.Rows = append(tableAddressSet.Rows,
			&loggerExporter.RowValue{
				FieldValue: []*loggerExporter.FieldValue{
					{Data: &loggerExporter.FieldValue_S{S: batchID}},
					{Data: &loggerExporter.FieldValue_S{S: addresSsetID}},
					{Data: &loggerExporter.FieldValue_S{S: addressSetItem.GetString("name")}},
					{Data: &loggerExporter.FieldValue_S{S: addressSetItem.GetString("description")}},
					{Data: &loggerExporter.FieldValue_S{S: addressSetItem.GetString("zone")}},
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
			tableAddress.Rows = append(tableAddress.Rows,
				&loggerExporter.RowValue{
					FieldValue: []*loggerExporter.FieldValue{
						{Data: &loggerExporter.FieldValue_S{S: addresSsetID}},
						{Data: &loggerExporter.FieldValue_I{I: AddressId_AddressSet}},
						{Data: &loggerExporter.FieldValue_S{S: utils.GetUUID()}},
						{Data: &loggerExporter.FieldValue_I{I: addressType}},
						{Data: &loggerExporter.FieldValue_S{S: address}},
						{Data: &loggerExporter.FieldValue_I{I: int32(addressItem.GetInt("v4"))}},
						{Data: &loggerExporter.FieldValue_S{S: addressItem.GetString("end")}},
						{Data: &loggerExporter.FieldValue_I{I: int32(addressItem.GetInt("mask"))}},
						{Data: &loggerExporter.FieldValue_S{S: addressItem.GetString("name")}},
					},
				},
			)
		}
	}
	return tableAddressSet, tableAddress
}

func convertServiceSetInfo(batchID string, serviceSet []*jjson.JsonObject) (*loggerExporter.TableData, *loggerExporter.TableData) {
	tableServiceSet := &loggerExporter.TableData{
		TableName: "firewall_serviceset",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "batch_id", ColumnType: 5},
			{ColumnName: "serviceset_id", ColumnType: 5},
			{ColumnName: "name", ColumnType: 5},
			{ColumnName: "description", ColumnType: 5},
		},
	}
	tableService := &loggerExporter.TableData{
		TableName: "firewall_service_detail",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "service_id", ColumnType: 5},
			{ColumnName: "id_type", ColumnType: 1},
			{ColumnName: "service_detail_id", ColumnType: 5},
			{ColumnName: "protocol", ColumnType: 5},
			{ColumnName: "source_port_from", ColumnType: 1},
			{ColumnName: "source_port_to", ColumnType: 1},
			{ColumnName: "destination_port_from", ColumnType: 1},
			{ColumnName: "destination_port_to", ColumnType: 1},
		},
	}
	if serviceSet == nil {
		return tableServiceSet, tableService
	}
	for _, serviceSetItem := range serviceSet {
		serviceSetID := utils.GetUUID()
		tableServiceSet.Rows = append(tableServiceSet.Rows,
			&loggerExporter.RowValue{
				FieldValue: []*loggerExporter.FieldValue{
					{Data: &loggerExporter.FieldValue_S{S: batchID}},
					{Data: &loggerExporter.FieldValue_S{S: serviceSetID}},
					{Data: &loggerExporter.FieldValue_S{S: serviceSetItem.GetString("name")}},
					{Data: &loggerExporter.FieldValue_S{S: serviceSetItem.GetString("description")}},
				},
			},
		)
		for _, serviceItem := range serviceSetItem.GetJsonArray("service") {
			tableService.Rows = append(tableService.Rows,
				&loggerExporter.RowValue{
					FieldValue: []*loggerExporter.FieldValue{
						{Data: &loggerExporter.FieldValue_S{S: serviceSetID}},
						{Data: &loggerExporter.FieldValue_I{I: 0}},
						{Data: &loggerExporter.FieldValue_S{S: utils.GetUUID()}},
						{Data: &loggerExporter.FieldValue_S{S: serviceItem.GetString("protocol")}},
						{Data: &loggerExporter.FieldValue_S{S: serviceItem.GetString("source_port_from")}},
						{Data: &loggerExporter.FieldValue_S{S: serviceItem.GetString("source_port_to")}},
						{Data: &loggerExporter.FieldValue_S{S: serviceItem.GetString("destination_port_from")}},
						{Data: &loggerExporter.FieldValue_S{S: serviceItem.GetString("destination_port_to")}},
					},
				},
			)
		}
	}
	return tableServiceSet, tableService
}

func convertDomainSetInfo(batchID string, domainSet []*jjson.JsonObject) (*loggerExporter.TableData, *loggerExporter.TableData) {
	tableDomainSet := &loggerExporter.TableData{
		TableName: "firewall_domainset",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "batch_id", ColumnType: 5},
			{ColumnName: "domainset_id", ColumnType: 5},
			{ColumnName: "name", ColumnType: 5},
			{ColumnName: "description", ColumnType: 5},
		},
	}
	tableDomain := &loggerExporter.TableData{
		TableName: "firewall_domain_detail",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "domainset_id", ColumnType: 5},
			{ColumnName: "domain_detail_id", ColumnType: 5},
			{ColumnName: "name", ColumnType: 5},
		},
	}
	if domainSet == nil {
		return tableDomainSet, tableDomain
	}
	for _, domainSetItem := range domainSet {
		domainSetID := utils.GetUUID()
		tableDomainSet.Rows = append(tableDomainSet.Rows,
			&loggerExporter.RowValue{
				FieldValue: []*loggerExporter.FieldValue{
					{Data: &loggerExporter.FieldValue_S{S: batchID}},
					{Data: &loggerExporter.FieldValue_S{S: domainSetID}},
					{Data: &loggerExporter.FieldValue_S{S: domainSetItem.GetString("name")}},
					{Data: &loggerExporter.FieldValue_S{S: domainSetItem.GetString("description")}},
				},
			},
		)
		for _, domainItem := range domainSetItem.GetJsonArray("domains") {
			tableDomain.Rows = append(tableDomain.Rows,
				&loggerExporter.RowValue{
					FieldValue: []*loggerExporter.FieldValue{
						{Data: &loggerExporter.FieldValue_S{S: domainSetID}},
						{Data: &loggerExporter.FieldValue_S{S: utils.GetUUID()}},
						{Data: &loggerExporter.FieldValue_S{S: domainItem.GetString("name")}},
					},
				},
			)
		}
	}
	return tableDomainSet, tableDomain
}

func convertZoneSetInfo(batchID string, zoneSet []*jjson.JsonObject) (*loggerExporter.TableData, *loggerExporter.TableData) {
	tableZoneSet := &loggerExporter.TableData{
		TableName: "firewall_zoneset",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "batch_id", ColumnType: 5},
			{ColumnName: "zoneset_id", ColumnType: 5},
			{ColumnName: "name", ColumnType: 5},
			{ColumnName: "description", ColumnType: 5},
			{ColumnName: "priority", ColumnType: 1},
		},
	}
	tableZone := &loggerExporter.TableData{
		TableName: "firewall_zone_detail",
		Columns: []*loggerExporter.ColumnData{
			{ColumnName: "zoneset_id", ColumnType: 5},
			{ColumnName: "zone_detail_id", ColumnType: 5},
			{ColumnName: "interface_name", ColumnType: 5},
		},
	}
	if zoneSet == nil {
		return tableZoneSet, tableZone
	}
	for _, zoneSetItem := range zoneSet {
		zoneSetID := utils.GetUUID()
		tableZoneSet.Rows = append(tableZoneSet.Rows,
			&loggerExporter.RowValue{
				FieldValue: []*loggerExporter.FieldValue{
					{Data: &loggerExporter.FieldValue_S{S: batchID}},
					{Data: &loggerExporter.FieldValue_S{S: zoneSetID}},
					{Data: &loggerExporter.FieldValue_S{S: zoneSetItem.GetString("name")}},
					{Data: &loggerExporter.FieldValue_S{S: zoneSetItem.GetString("description")}},
					{Data: &loggerExporter.FieldValue_I{I: int32(zoneSetItem.GetInt("priority"))}},
				},
			},
		)
		for _, zoneItem := range zoneSetItem.GetJsonArray("interfaces") {
			tableZone.Rows = append(tableZone.Rows,
				&loggerExporter.RowValue{
					FieldValue: []*loggerExporter.FieldValue{
						{Data: &loggerExporter.FieldValue_S{S: zoneSetID}},
						{Data: &loggerExporter.FieldValue_S{S: utils.GetUUID()}},
						{Data: &loggerExporter.FieldValue_S{S: zoneItem.String()}},
					},
				},
			)
		}
	}
	return tableZoneSet, tableZone
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
