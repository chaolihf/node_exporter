//go:build npu
// +build npu

package npu

import (
	"net/http"

	"context"
	"fmt"

	"github.com/chaolihf/mind-cluster/component/ascend-common/common-utils/hwlog"
	"github.com/chaolihf/mind-cluster/component/ascend-common/devmanager"
	"github.com/chaolihf/mind-cluster/component/ascend-common/devmanager/common"
	"github.com/chaolihf/mind-cluster/component/ascend-common/devmanager/dcmi"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var HwLogConfig = &hwlog.LogConfig{
	LogFileName:   "npu-exporter.log",
	ExpiredTime:   hwlog.DefaultExpiredTime,
	CacheSize:     hwlog.DefaultCacheSize,
	MaxBackups:    1,
	MaxAge:        7,
	MaxLineLength: 1024,
}

var logger log.Logger
var deviceManager dcmi.DcDriverInterface

type npuCollector struct {
}

func (collector *npuCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (collector *npuCollector) Collect(ch chan<- prometheus.Metric) {
	cardNum, cardIDList, err := deviceManager.DcGetCardList()
	// cardNum, cardIDList, err := deviceManager.DcGetLogicIDList()
	if err != nil {
		level.Error(logger).Log("msg", "error on get npu cardlist ", err)
	}
	deviceCountMetric := prometheus.NewDesc("npu_card_count", "", nil, nil)
	ch <- prometheus.MustNewConstMetric(deviceCountMetric, prometheus.CounterValue, float64(cardNum))
	var tags = make(map[string]string)
	for _, cardID := range cardIDList {
		deviceNum, err := deviceManager.DcGetDeviceNumInCard(cardID)
		if err != nil {
			level.Error(logger).Log("msg", "error on get device id %s\n", err)
		}
		tags["index"] = fmt.Sprintf("%d", cardID)
		for deviceID := int32(0); deviceID < deviceNum; deviceID++ {
			logicID, err := deviceManager.DcGetDeviceMainBoardInfo(cardID, deviceID)
			tags["uuid"] = fmt.Sprintf("%d", logicID)
			voltageInfo, err := deviceManager.DcGetDeviceVoltage(cardID, int32(deviceID))
			if err != nil {
				level.Error(logger).Log("msg", "error on get device voltageInfo id %s", err)
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_voltage", "", nil, tags),
				prometheus.CounterValue, float64(voltageInfo))
			aiCoreUtilization, err := deviceManager.DcGetDeviceUtilizationRate(cardID, int32(deviceID), common.AICore)
			if err != nil {
				level.Error(logger).Log("msg", "error on get device aiCoreUtilization id %s", err)
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_aicore_utilization", "", nil, tags),
				prometheus.CounterValue, float64(aiCoreUtilization))
			overAllUtilization, err := deviceManager.DcGetDeviceUtilizationRate(cardID, int32(deviceID), common.Overall)
			if err != nil {
				level.Error(logger).Log("msg", "error on get device overAllUtilization id %s", err)
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_overall_utilization", "", nil, tags),
				prometheus.CounterValue, float64(overAllUtilization))
			powerInfo, err := deviceManager.DcGetDevicePowerInfo(cardID, int32(deviceID))
			if err != nil {
				level.Error(logger).Log("msg", "error on get device powerInfo id %s", err)
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_power", "", nil, tags),
				prometheus.CounterValue, float64(powerInfo))
			temperatureInfo, err := deviceManager.DcGetDeviceTemperature(cardID, int32(deviceID))
			if err != nil {
				level.Error(logger).Log("msg", "error on get device temperatureInfo id %s", err)
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_temperature", "", nil, tags),
				prometheus.CounterValue, float64(temperatureInfo))
			highBandwidthMemoryInfo, err := deviceManager.DcGetHbmInfo(cardID, int32(deviceID))
			if err != nil {
				level.Error(logger).Log("msg", "error on get device highBandwidthMemoryInfo id %s", err)
			}
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_highbandwidth_memory_size", "", nil, tags),
				prometheus.CounterValue, float64(highBandwidthMemoryInfo.MemorySize))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_highbandwidth_memory_frequency", "", nil, tags),
				prometheus.CounterValue, float64(highBandwidthMemoryInfo.Frequency))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_highbandwidth_memory_usage", "", nil, tags),
				prometheus.CounterValue, float64(highBandwidthMemoryInfo.Usage))
			ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_highbandwidth_memory_temp", "", nil, tags),
				prometheus.CounterValue, float64(highBandwidthMemoryInfo.Temp))
			devProcessInfo, err := deviceManager.DcGetDevProcessInfo(cardID, int32(deviceID))
			if err != nil {
				level.Error(logger).Log("msg", "error on get device devProcessInfo id %s", err)
			}
			var processTags = make(map[string]string)
			processTags["index"] = fmt.Sprintf("%d", cardID)
			processTags["uuid"] = fmt.Sprintf("%d", logicID)
			for _, processInfo := range devProcessInfo.DevProcArray {
				processTags["pid"] = fmt.Sprintf("%d", processInfo.Pid)
				processTags["usedGpuMemory"] = fmt.Sprintf("%.2f", processInfo.MemUsage)
				ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("npu_device_process_info", "", nil, processTags),
					prometheus.CounterValue, float64(0))
			}
			fmt.Printf("cardID %d, deviceID %d,devProcessInfo %v\n", cardID, deviceID, devProcessInfo)
		}

	}
}

func init() {
	if err := hwlog.InitRunLogger(HwLogConfig, context.Background()); err != nil {
		level.Error(logger).Log("msg", "hwlog init failed, error is ", err)
		return
	}
	dmgr, err := devmanager.AutoInit("")
	if err != nil {
		level.Error(logger).Log("msg", "new npu collector failed, error is ", err)
		return
	}
	deviceManager = dmgr.DcMgr
}

func SetLogger(globalLogger log.Logger) {
	logger = globalLogger
}
func RequestHandler(w http.ResponseWriter, r *http.Request) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(&npuCollector{})
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}
