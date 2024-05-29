package script

import (
	"fmt"
	"net/http"
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
	metrics := getRunScriptResult()
	if metrics != nil {
		for _, metric := range metrics {
			ch <- metric
		}
	}
}

func getRunScriptResult() []prometheus.Metric {
	var metrics []prometheus.Metric
	session := sshclient.NewSshSession("134.95.237.121:2222", "nmread", "Siemens#202405", 10)
	if session == nil {
		return nil
	}
	content, err := session.ExecuteMoreCommand("display arp", "---- More ----", "<TDL-JF-9310-1>")
	if err != nil {
		return nil
	}
	rows := strings.Split(content, "\r\n")
	index := 0
	for _, row := range rows {
		var tags = make(map[string]string)
		columns := strings.Split(row, " ")
		for _, column := range columns {
			if len(column) > 0 {
				tags[fmt.Sprintf("col%d", index)] = column
				index = index + 1
			}
		}
		scriptMetric := prometheus.NewDesc(fmt.Sprintf("arp_addresss%d", index), "", nil, tags)
		metric := prometheus.MustNewConstMetric(scriptMetric, prometheus.CounterValue, 1)
		metrics = append(metrics, metric)
	}
	session.Close()
	return metrics
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
