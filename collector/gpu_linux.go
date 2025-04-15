package collector

import (
	"ascend-common/common-utils/hwlog"
	"ascend-common/devmanager"
	nvidiaLog "log"
	"os"
	"strconv"
	"time"

	// "ascend-common/common-utils/hwlog"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	huaweiLog "github.com/chaolihf/node_exporter/collector/huawei-utils/logger"
	versions "github.com/chaolihf/node_exporter/collector/huawei-versions"

	// "github.com/chaolihf/node_exporter/collector/huawei-collector/common"
	// "github.com/chaolihf/node_exporter/collector/huawei-collector/container"

	colcommon "github.com/chaolihf/node_exporter/collector/huawei-collector/common"
	"github.com/chaolihf/node_exporter/collector/huawei-collector/container"
	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

func init() {
	registerCollector("gpu", true, newGpuInfoCollector)
}

var (
	containerMode = ""
	containerd    = ""
	endpoint      = ""
	n             *CollectorForPrometheus
)

const (
	containerModeDocker     = "docker"
	containerModeContainerd = "containerd"
	containerModeIsula      = "isula"
)

/*
1. 定义GPU信息收集器,gpuType可选：huawei、nvidia、moore
2. 确认是否启用GPU信息收集器
*/
type GpuInfoCollector struct {
	enable  bool
	gpuType string
}

func newGpuInfoCollector(g_logger log.Logger) (Collector, error) {
	logger = g_logger
	filePath := "config.json"
	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Log("读取文件出错:"+filePath, err)
		return &GpuInfoCollector{
			enable: false,
		}, nil
	} else {
		jsonConfigInfos, err := jjson.NewJsonObject([]byte(content))
		if err != nil {
			logger.Log("JSON文件格式出错:", err)
			return &GpuInfoCollector{
				enable: false,
			}, err
		} else {
			jsonGpuCollectInfo := jsonConfigInfos.GetJsonObject("gpuCollect")
			enable := jsonGpuCollectInfo.GetBool("enable")
			gpuType := jsonGpuCollectInfo.GetString("gpuType")
			//如果采集华为GPU，则需要初始化collector
			if gpuType == "huawei" {
				dmgr, err := devmanager.AutoInit("")
				if err != nil {
					huaweiLog.Errorf("new npu collector failed, error is %v", err)
					return &GpuInfoCollector{
						enable: false,
					}, err
				}
				huaweiLog.Infof("npu exporter starting and the version is %s", versions.BuildVersion)
				deviceParser := container.MakeDevicesParser(readCntMonitoringFlags())
				defer deviceParser.Close()
				if err := deviceParser.Init(); err != nil {
					huaweiLog.Errorf("failed to init devices parser: %v", err)
				}
				deviceParser.Timeout = time.Duration(60) * time.Second
				colcommon.Collector = colcommon.NewNpuCollector(65*time.Second, time.Duration(60)*time.Second, deviceParser, dmgr)
				n = &CollectorForPrometheus{
					collector: colcommon.Collector,
				}
			}
			return &GpuInfoCollector{
				enable:  enable,
				gpuType: gpuType,
			}, nil
		}
	}
}

func readCntMonitoringFlags() container.CntNpuMonitorOpts {
	opts := container.CntNpuMonitorOpts{UserBackUp: true}
	switch containerMode {
	case containerModeDocker:
		opts.EndpointType = container.EndpointTypeDockerd
		opts.OciEndpoint = container.DefaultDockerAddr
		opts.CriEndpoint = container.DefaultDockerShim
	case containerModeContainerd:
		opts.EndpointType = container.EndpointTypeContainerd
		opts.OciEndpoint = container.DefaultContainerdAddr
		opts.CriEndpoint = container.DefaultContainerdAddr
	case containerModeIsula:
		opts.EndpointType = container.EndpointTypeIsula
		opts.OciEndpoint = container.DefaultIsuladAddr
		opts.CriEndpoint = container.DefaultIsuladAddr
	default:
		hwlog.RunLog.Error("invalid container mode setting,reset to docker")
		opts.EndpointType = container.EndpointTypeDockerd
		opts.OciEndpoint = container.DefaultDockerAddr
		opts.CriEndpoint = container.DefaultDockerShim
	}
	if containerd != "" {
		opts.OciEndpoint = containerd
		opts.UserBackUp = false
	}
	if endpoint != "" {
		opts.CriEndpoint = endpoint
		opts.UserBackUp = false
	}
	return opts
}

func (collector *GpuInfoCollector) Update(ch chan<- prometheus.Metric) error {
	if collector.enable {
		if collector.gpuType == "huawei" {
			//开始采集相关显卡指标
			containerMap := colcommon.GetContainerNPUInfo(n.collector)
			chips := colcommon.GetChipListWithVNPU(n.collector)
			collectChain(ch, n, containerMap, chips, colcommon.ChainForSingleGoroutine)
			collectChain(ch, n, containerMap, chips, colcommon.ChainForMultiGoroutine)
		} else if collector.gpuType == "nvidia" {
			metrics := collectNvidiaMetric()
			for _, metric := range metrics {
				ch <- metric
			}
		} else {
			logger.Log("GPU类型不支持:", collector.gpuType)
			return nil
		}
	}
	return nil
}

type CollectorForPrometheus struct {
	collector *colcommon.NpuCollector
}

func collectChain(ch chan<- prometheus.Metric, n *CollectorForPrometheus, containerMap map[int32]container.DevicesInfo,
	chips []colcommon.HuaWeiAIChip, chain []colcommon.MetricsCollector) {
	if ch == nil {
		logger.Log("ch is nil")
		return
	}
	for _, collector := range chain {
		collector.UpdatePrometheus(ch, n.collector, containerMap, chips)
	}
}

func collectNvidiaMetric() []prometheus.Metric {
	ret := nvml.Init()
	if ret != nvml.SUCCESS {
		nvidiaLog.Fatalf("Unable to initialize NVML: %v", nvml.ErrorString(ret))
	}
	defer func() {
		ret := nvml.Shutdown()
		if ret != nvml.SUCCESS {
			nvidiaLog.Fatalf("Unable to shutdown NVML: %v", nvml.ErrorString(ret))
		}
	}()

	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		nvidiaLog.Fatalf("Unable to get device count: %v", nvml.ErrorString(ret))
	}

	var metrics []prometheus.Metric

	//遍历每一个GPU卡
	for i := 0; i < count; i++ {
		device, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			nvidiaLog.Fatalf("Unable to get device at index %d: %v", i, nvml.ErrorString(ret))
		}

		uuid, ret := device.GetUUID()
		if ret != nvml.SUCCESS {
			nvidiaLog.Fatalf("Unable to get uuid of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		utilization, ret := device.GetUtilizationRates()
		if ret != nvml.SUCCESS {
			nvidiaLog.Fatalf("Unable to get utilization of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		memory, ret := device.GetMemoryInfo()
		if ret != nvml.SUCCESS {
			nvidiaLog.Fatalf("Unable to get memory of device at index %d: %v", i, nvml.ErrorString(ret))
		}

		gpuUtilizationMetric := createGpuUtilizationMetric(strconv.Itoa(i), uuid, float64(utilization.Gpu))
		memoryUtilizationMetric := creatMemoryUtilizationMetric(strconv.Itoa(i), uuid, float64(utilization.Memory))
		memoryUsedMetric := creatMemoryMetric(strconv.Itoa(i), uuid, strconv.FormatUint(memory.Total, 10), float64(memory.Used))

		metrics = append(metrics, gpuUtilizationMetric, memoryUtilizationMetric, memoryUsedMetric)
	}
	return metrics
}

/*
生成GPU利用率指标
*/
func createGpuUtilizationMetric(id string, uuid string, utilization float64) prometheus.Metric {
	gpuUtilization := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gpu_utilization",
			Help: "Percent of time over the past sample period during which one or more kernels was executing on the GPU.",
		},
		[]string{"id", "uuid"},
	)
	gpuUtilizationMetric := gpuUtilization.WithLabelValues(id, uuid)
	gpuUtilizationMetric.Set(utilization)
	return gpuUtilizationMetric
}

/*
生成memory利用率指标
*/
func creatMemoryUtilizationMetric(id string, uuid string, utilization float64) prometheus.Metric {
	memoryUtilization := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "memory_utilization",
			Help: "Percent of time over the past sample period during which global (device) memory was being read or written.",
		},
		[]string{"id", "uuid"},
	)
	memoryUtilizationMetric := memoryUtilization.WithLabelValues(id, uuid)
	memoryUtilizationMetric.Set(utilization)
	return memoryUtilizationMetric
}

/*
生成memory使用及总量指标
*/
func creatMemoryMetric(id string, uuid string, total string, utilization float64) prometheus.Metric {
	memoryUsed := promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gpu_used_memory",
			Help: "Sum of Reserved and Allocated device memory (in bytes). Note that the driver/GPU always sets aside a small amount of memory for bookkeeping ",
		},
		[]string{"id", "uuid", "total"},
	)
	memoryUsedMetric := memoryUsed.WithLabelValues(id, uuid, total)
	memoryUsedMetric.Set(utilization)
	return memoryUsedMetric
}
