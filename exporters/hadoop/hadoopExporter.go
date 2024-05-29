package hadoop

import (
	"encoding/json"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"

	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/go-resty/resty/v2"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type ExporterConfig struct {
	ListenAddress string         `json:"listen"`
	Codes         []CodeMap      `json:"codeMaps"`
	Metrics       []MetricType   `json:"metrics"`
	TargetServers []TargetServer `json:"servers"`
}

type CodeMap struct {
	Code  string `json:"name"`
	Value int    `json:"value"`
}

type MetricType struct {
	Name string `json:"name"`
}

type TargetServer struct {
	Name   string `json:"name"`
	Url    string `json:"url"`
	Module string `json:"module"`
}

var logger log.Logger
var client *resty.Client

type beanHandler func(beanInfo *jjson.JsonObject, keySet map[string][]string, modulePrefix string, isShowAll bool) []prometheus.Metric

var handlerMap map[string]beanHandler
var exporterInfo ExporterConfig

type hadoopCollector struct {
	remoteUrl    string
	modulePrefix string
	showAll      bool
}

var isHadoopInited = false

func (collector *hadoopCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (collector *hadoopCollector) Collect(ch chan<- prometheus.Metric) {
	metrics := getJmxInfo(collector.remoteUrl, collector.modulePrefix, collector.showAll)
	for _, metric := range metrics {
		ch <- metric
	}
}

func getJmxInfo(url string, modulePrefix string, isShowAll bool) []prometheus.Metric {
	var metrics []prometheus.Metric
	level.Info(logger).Log("info", fmt.Sprintf("get url %s", url))
	resp, err := client.R().EnableTrace().Get(url)
	if err != nil {
		level.Error(logger).Log("err", err.Error())
	}
	jsonInfo, _ := jjson.FromBytes(resp.Body())
	beanInfos := jsonInfo.GetJsonArray("beans")
	var keySet = make(map[string][]string)
	for _, beanInfo := range beanInfos {
		beanName := beanInfo.GetString("name")
		if strings.HasPrefix(beanName, "Hadoop:") {
			handler := handlerMap[beanName]
			if handler == nil {
				handler = getBeanMetrics
			}
			metrics = append(metrics, handler(beanInfo, keySet, modulePrefix, isShowAll)...)
		}
	}
	return metrics
}

// @title
func getAttributeValue(attrValue *jjson.JsonObject) float64 {
	var value float64
	switch attrValue.VType {
	case reflect.Float64:
		{
			value = attrValue.Value.(float64)
		}
	case reflect.Int32:
		{
			value = float64(attrValue.Value.(int64))
		}
	case reflect.String:
		{
			value = 0
			data := attrValue.Value.(string)
			for _, codeInfo := range exporterInfo.Codes {
				if codeInfo.Code == data {
					value = float64(codeInfo.Value)
					break
				}
			}
		}
	}
	return value
}

func init() {
	client = resty.New()
	handlerMap = make(map[string]beanHandler)
	filePath := "hadoopConfig.json"
	content, err := os.ReadFile(filePath)
	if err != nil {
		stdlog.Printf("读取文件出错:%s,%s", filePath, err.Error())
	} else {
		err := json.Unmarshal(content, &exporterInfo)
		if err != nil {
			stdlog.Printf("解析文件出错:%s", filePath+err.Error())
		}
	}
	registerNameHandler("Hadoop:service=HBase,name=RegionServer,sub=Regions", handlerRegionServerRegions)
	registerNameHandler("Hadoop:service=HBase,name=RegionServer,sub=Tables", handlerRegionServerRegions)
	registerNameHandler("Hadoop:service=HBase,name=RegionServer,sub=TableLatencies", handlerRegionServerRegions)
}

func SetLogger(g_logger log.Logger) {
	if !isHadoopInited {
		logger = g_logger
		isHadoopInited = true
	}
}
func RequestHandler(w http.ResponseWriter, r *http.Request) {

	registry := prometheus.NewRegistry()
	params := r.URL.Query()
	targetName := params.Get("target")
	module := params.Get("module")
	if targetName == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing target parameter!"))
		return
	}
	var targetUrl string = ""
	var defaultModule string = ""
	for _, targetServer := range exporterInfo.TargetServers {
		if targetServer.Name == targetName {
			targetUrl = targetServer.Url
			defaultModule = targetServer.Module
			break
		}
	}
	if targetUrl == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("can't find target name on server " + targetName))
		return
	}
	if module == "" {
		if defaultModule == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("missing module parameter!"))
			return
		}
		module = defaultModule
	}
	showAllParam := params.Get("showall")
	var isShowAll bool = false
	if showAllParam == "1" {
		isShowAll = true
	}
	registry.MustRegister(&hadoopCollector{remoteUrl: targetUrl, modulePrefix: module, showAll: isShowAll})

	// probeSuccessGauge := prometheus.NewGauge(prometheus.GaugeOpts{
	// 	Name: "probe_success",
	// 	Help: "Displays whether or not the probe was a success",
	// })
	// registry.MustRegister(probeSuccessGauge)
	// probeSuccessGauge.Set(1010)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func registerNameHandler(name string, handler beanHandler) {
	handlerMap[name] = handler
}

func getBeanMetrics(beanInfo *jjson.JsonObject, keySet map[string][]string, modulePrefix string, isShowAll bool) []prometheus.Metric {
	var metrics []prometheus.Metric
	var tags = make(map[string]string)
	metrixPerfix := getNameLabelInfo(beanInfo, tags, modulePrefix)
	tagString := getTagNames(tags)
	for _, key := range beanInfo.GetKeys() {
		if key != "name" && key != "modelerType" && !strings.HasPrefix(key, "tag.") {
			metricName := renameMetricName(keySet, metrixPerfix+"_"+key, tagString)
			if isShowAll || isInExportList(metricName) {
				value := getAttributeValue(beanInfo.Attributes[key])
				name := strings.ReplaceAll(beanInfo.Attributes["name"].Value.(string), "\"", "")
				hadoopMetric := prometheus.NewDesc(metricName, fmt.Sprintf("bean path=>%s=>%s", name, key), nil, tags)
				metric := prometheus.MustNewConstMetric(hadoopMetric, prometheus.CounterValue, value)
				metrics = append(metrics, metric)
			}
		}
	}
	return metrics
}

// @title handler for hbase region server
//因为存在指标名称小写一样的问题，对于小写一样但指标名称不一样的进行编号；key为指标名称的小写，

func handlerRegionServerRegions(beanInfo *jjson.JsonObject, keySet map[string][]string, modulePrefix string, isShowAll bool) []prometheus.Metric {
	var metrics []prometheus.Metric
	var tags = make(map[string]string)
	metrixPerfix := getNameLabelInfo(beanInfo, tags, modulePrefix)
	tagString := getTagNames(tags)
	for _, key := range beanInfo.GetKeys() {
		if key != "name" && key != "modelerType" && !strings.HasPrefix(key, "tag.") {
			metricIndex := strings.Index(key, "_metric_")
			if metricIndex != -1 {
				parts := strings.Split(key, "_")
				var regionIndex int
				metriTag := tagString
				for index, part := range parts {
					if part == "region" {
						tagName := strings.Join(parts[3:index], "_")
						metriTag = metriTag + "_tableName"
						tags["tableName"] = tagName
						regionIndex = index
					} else if part == "metric" {
						tagName := strings.Join(parts[regionIndex+1:index], "_")
						metriTag = metriTag + "_tableId"
						tags["tableId"] = tagName
					}
				}
				metricName := renameMetricName(keySet, metrixPerfix+"_"+key[metricIndex+8:], metriTag)
				if isShowAll || isInExportList(metricName) {
					value := getAttributeValue(beanInfo.Attributes[key])
					name := strings.ReplaceAll(beanInfo.Attributes["name"].Value.(string), "\"", "")
					hadoopMetric := prometheus.NewDesc(metricName, fmt.Sprintf("bean path=>%s=>%s", name, key), nil, tags)
					metric := prometheus.MustNewConstMetric(hadoopMetric, prometheus.CounterValue, value)
					metrics = append(metrics, metric)
				}
				delete(tags, "tableName")
				delete(tags, "tableId")
			}
		}
	}
	return metrics
}

func isInExportList(metricName string) bool {
	if exporterInfo.Metrics != nil {
		for _, metricType := range exporterInfo.Metrics {
			if metricName == metricType.Name {
				return true
			}
		}
		return false
	}
	return true
}

func getTagNames(tags map[string]string) string {
	result := []string{}
	for key, _ := range tags {
		result = append(result, key)
	}
	sort.Strings(result)
	return strings.Join(result, "_")
}

// @Title 替换特殊字符，对重复的指标名称进行替换
func renameMetricName(keySet map[string][]string, metricName string, tagString string) string {
	metricName = strings.ReplaceAll(metricName, "(", "")
	metricName = strings.ReplaceAll(metricName, ")", "")
	metricName = strings.ReplaceAll(metricName, ".", "_")
	metricName = strings.ReplaceAll(metricName, "-", "_")
	metricName = strings.ReplaceAll(metricName, ":", "_")
	shortMetricName := strings.ToLower(metricName)
	dupMetrics := keySet[shortMetricName]
	if dupMetrics == nil {
		keySet[shortMetricName] = []string{metricName + "_" + tagString}
	} else {
		var index int
		var oriName string
		isFind := false
		for index, oriName = range dupMetrics {
			if oriName == metricName+"_"+tagString {
				isFind = true
				break
			}
		}
		if isFind {
			if index != 0 {
				metricName = fmt.Sprintf("%s%d", metricName, index-1)
			}
		} else {
			dupMetrics = append(dupMetrics, metricName+"_"+tagString)
			keySet[shortMetricName] = dupMetrics
			metricName = fmt.Sprintf("%s%d", metricName, index)
		}
	}
	return metricName
}

// @title get metric name and label information
func getNameLabelInfo(beanInfo *jjson.JsonObject, tags map[string]string, modulePrefix string) string {
	var metrixPerfix string
	for _, key := range beanInfo.GetKeys() {
		switch key {
		case "name":
			{
				name := beanInfo.GetString("name")
				prefix := []string{"Hadoop"}
				for _, label := range strings.Split(name[7:], ",") {
					items := strings.Split(label, "=")
					if items[0] == "service" {
						prefix = append(prefix, items[1])
					} else if items[0] != "name" {
						tags[items[0]] = items[1]
					}
				}

				metrixPerfix = strings.Join(prefix, "_")
				if modulePrefix != "" {
					metrixPerfix = metrixPerfix + "_" + modulePrefix
				}
			}
		case "modelerType":
			{
				//tags["modelerTypee"] = beanInfo.GetString("modelerType")
			}
		default:
			{
				if strings.HasPrefix(key, "tag.") {
					tags[key[4:]] = beanInfo.GetString(key)
				}
			}
		}
	}
	return metrixPerfix
}
