package script

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/chaolihf/node_exporter/pkg/clients/sshclient"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var logger log.Logger

type scriptCollector struct {
	remoteUrl    string
	modulePrefix string
	showAll      bool
}

var isScriptInited = false

func (collector *scriptCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (collector *scriptCollector) Collect(ch chan<- prometheus.Metric) {
	//metrics := getHuaweiScriptResult()
	metrics := getH3ScriptResult()
	for _, metric := range metrics {
		ch <- metric
	}
}

func getH3ScriptResult() []prometheus.Metric {
	session := sshclient.NewSshSession("", "", "", 10)
	if session == nil {
		return nil
	}
	defer session.Close()
	content, _ := session.ExecuteCommand("display arp", "Aging Type \r\r\n")
	tableInfo := ParseTableData(content, "\r\r\n", `(.{16})(.{15})(.{11})(.{25})(.{6})(.*)`)
	metrics := CreateMetrics(tableInfo,
		[]string{"ip", "mac", "vlan", "interface", "expire", "type", "instance"})
	return metrics
}

func getHuaweiScriptResult() []prometheus.Metric {
	session := sshclient.NewSshSession("", "", "", 10)
	if session == nil {
		return nil
	}
	defer session.Close()
	content, err := session.ExecuteMoreCommand("display arp",
		"---- More ----", "<TDL-JF-9310-1>", "\x1B[42D",
		"------------------------------------------------------------------------------\r\n",
		"------------------------------------------------------------------------------\r\n",
		false)
	if err != nil {
		return nil
	}
	// file, _ := os.Create("temp.txt")
	// file.WriteString(content)
	// file.Close()
	tableInfo := ParseTableData(content, "\r\n", `(.{16})(.{16})(.{10})(.{12})(.{15})(.*)`)
	metrics := CreateMetrics(tableInfo,
		[]string{"ip", "mac", "expire", "type", "interface", "instance", "vlan"})

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

}

func SetLogger(g_logger log.Logger) {
	if !isScriptInited {
		logger = g_logger
		isScriptInited = true
	}
}
func RequestHandler(w http.ResponseWriter, r *http.Request) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(&scriptCollector{})
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}
