//go:build gpu
// +build gpu

/*
gpu exporter
*/
package gpu

import (
	"fmt"
	"net/http"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var logger log.Logger

type gpuCollector struct {
}

func (collector *gpuCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (collector *gpuCollector) Collect(ch chan<- prometheus.Metric) {
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		level.Error(logger).Log("msg", "Unable to get device count:", "err", nvml.ErrorString(ret))
	}
	deviceCountMetric := prometheus.NewDesc("gpu_device_count", "", nil, nil)
	ch <- prometheus.MustNewConstMetric(deviceCountMetric, prometheus.CounterValue, float64(count))
	var tags = make(map[string]string)
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, "err", nvml.ErrorString(ret))
		}
		uuid, ret := device.GetUUID()
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, " uuid ,err", nvml.ErrorString(ret))
		}
		tags["uuid"] = uuid
		tags["index"] = fmt.Sprintf("%d", i)
		memInfo, ret := device.GetMemoryInfo()
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, " memory,err", nvml.ErrorString(ret))
		}
		powerInfo, ret := device.GetPowerUsage()
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, " power,err", nvml.ErrorString(ret))
		}
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("gpu_total_memory", "", nil, tags),
			prometheus.CounterValue, float64(memInfo.Total/1024/1024))
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("gpu_used_memory", "", nil, tags),
			prometheus.CounterValue, float64(memInfo.Used/1024/1024))
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("gpu_free_memory", "", nil, tags),
			prometheus.CounterValue, float64(memInfo.Free/1024/1024))
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("gpu_used_power", "", nil, tags),
			prometheus.CounterValue, float64(powerInfo/1000))
		utilization, ret := device.GetUtilizationRates()
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, " utilization ,err", nvml.ErrorString(ret))
			continue
		}
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("gpu_util_memory", "", nil, tags),
			prometheus.CounterValue, float64(utilization.Memory))
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("gpu_util_gpu", "", nil, tags),
			prometheus.CounterValue, float64(utilization.Gpu))
		temperature, ret := device.GetTemperature(0)
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, " temperature ,err", nvml.ErrorString(ret))
			continue
		}
		ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("gpu_temperature", "", nil, tags),
			prometheus.CounterValue, float64(temperature))
		processComputeList, ret := device.GetComputeRunningProcesses()
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, " process ,err", nvml.ErrorString(ret))
			continue
		}
		processGraphicsList, ret := device.GetGraphicsRunningProcesses()
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, " process ,err", nvml.ErrorString(ret))
			continue
		}
		processMpsList, ret := device.GetMPSComputeRunningProcesses()
		if ret != nvml.SUCCESS {
			level.Error(logger).Log("msg", "Unable to get device ", i, " process ,err", nvml.ErrorString(ret))
			continue
		}
		combinedProcess := append(processComputeList, processGraphicsList...)
		processList := append(combinedProcess, processMpsList...)
		resultProcessList := []nvml.ProcessInfo{}
		uniqueMap := make(map[nvml.ProcessInfo]bool)
		for _, item := range processList {
			if _, exists := uniqueMap[item]; !exists {
				uniqueMap[item] = true
				resultProcessList = append(resultProcessList, item)
			}
		}
		processInfoDesc := prometheus.NewDesc("gpu_process_info", "GPU process info",
			[]string{"uuid", "index", "pid", "usedGpuMemory"}, nil)

		// 去重 set（避免完全相同的 label 集合重复上报）
		emitted := make(map[string]bool)

		for _, processInfo := range resultProcessList {
			pidStr := fmt.Sprintf("%d", processInfo.Pid)
			memStr := fmt.Sprintf("%d", processInfo.UsedGpuMemory/1024/1024)
			key := uuid + "|" + fmt.Sprintf("%d", i) + "|" + pidStr + "|" + memStr

			if emitted[key] {
				// 已上报，跳过
				continue
			}
			emitted[key] = true

			ch <- prometheus.MustNewConstMetric(processInfoDesc, prometheus.CounterValue, 0,
				uuid,
				fmt.Sprintf("%d", i),
				pidStr,
				memStr,
			)
		}
	}
}

func init() {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		level.Error(logger).Log("msg", "Unable to initialize NVML:", "err", nvml.ErrorString(ret))
	}
}

func SetLogger(globalLogger log.Logger) {
	logger = globalLogger
}
func RequestHandler(w http.ResponseWriter, r *http.Request) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(&gpuCollector{})
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}
