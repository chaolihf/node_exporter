package collector

import (
	// "ascend-common/common-utils/cache"
	// "ascend-common/common-utils/hwlog"
	// "ascend-common/devmanager"
	// "ascend-common/devmanager/common"

	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	// huaweiLog "github.com/chaolihf/node_exporter/collector/huawei-utils/logger"
	// versions "github.com/chaolihf/node_exporter/collector/huawei-versions"

	// "github.com/chaolihf/node_exporter/collector/huawei-collector/container"
	"maps"

	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	registerCollector("gpu", true, newGpuInfoCollector)
}

type requiredField struct {
	qField QField
	label  string
}

var (
	matchFirstCap = regexp.MustCompile("(.)([A-Z][a-z]+)")
	matchAllCap   = regexp.MustCompile("([a-z0-9])([A-Z])")
	//nolint:gochecknoglobals
	defaultRunCmd = func(cmd *exec.Cmd) error {
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("error running command: %w", err)
		}

		return nil
	}
	numericRegex = regexp.MustCompile(`[+-]?(\d*[.])?\d+`)
	//nolint:gochecknoglobals
	requiredFields = []requiredField{
		{qField: uuidQField, label: "uuid"},
		{qField: nameQField, label: "name"},
		{qField: driverModelCurrentQField, label: "driver_model_current"},
		{qField: driverModelPendingQField, label: "driver_model_pending"},
		{qField: vBiosVersionQField, label: "vbios_version"},
		{qField: driverVersionQField, label: "driver_version"},
	}
	fieldRegex = regexp.MustCompile(`(?m)\n\s*\n^"([^"]+)"`)
	//nolint:gochecknoglobals
	fallbackQFieldToRFieldMap = map[QField]RField{
		"timestamp":                         "timestamp",
		"driver_version":                    "driver_version",
		"count":                             "count",
		"name":                              "name",
		"serial":                            "serial",
		"uuid":                              "uuid",
		"pci.bus_id":                        "pci.bus_id",
		"pci.domain":                        "pci.domain",
		"pci.bus":                           "pci.bus",
		"pci.device":                        "pci.device",
		"pci.device_id":                     "pci.device_id",
		"pci.sub_device_id":                 "pci.sub_device_id",
		"pcie.link.gen.current":             "pcie.link.gen.current",
		"pcie.link.gen.max":                 "pcie.link.gen.max",
		"pcie.link.width.current":           "pcie.link.width.current",
		"pcie.link.width.max":               "pcie.link.width.max",
		"index":                             "index",
		"display_mode":                      "display_mode",
		"display_active":                    "display_active",
		"persistence_mode":                  "persistence_mode",
		"accounting.mode":                   "accounting.mode",
		"accounting.buffer_size":            "accounting.buffer_size",
		"driver_model.current":              "driver_model.current",
		"driver_model.pending":              "driver_model.pending",
		"vbios_version":                     "vbios_version",
		"inforom.img":                       "inforom.img",
		"inforom.oem":                       "inforom.oem",
		"inforom.ecc":                       "inforom.ecc",
		"inforom.pwr":                       "inforom.pwr",
		"gom.current":                       "gom.current",
		"gom.pending":                       "gom.pending",
		"fan.speed":                         "fan.speed [%]",
		"pstate":                            "pstate",
		"clocks_throttle_reasons.supported": "clocks_throttle_reasons.supported",
		"clocks_throttle_reasons.active":    "clocks_throttle_reasons.active",
		"clocks_throttle_reasons.gpu_idle":  "clocks_throttle_reasons.gpu_idle",
		"clocks_throttle_reasons.applications_clocks_setting": "clocks_throttle_reasons.applications_clocks_setting",
		"clocks_throttle_reasons.sw_power_cap":                "clocks_throttle_reasons.sw_power_cap",
		"clocks_throttle_reasons.hw_slowdown":                 "clocks_throttle_reasons.hw_slowdown",
		"clocks_throttle_reasons.hw_thermal_slowdown":         "clocks_throttle_reasons.hw_thermal_slowdown",
		"clocks_throttle_reasons.hw_power_brake_slowdown":     "clocks_throttle_reasons.hw_power_brake_slowdown",
		"clocks_throttle_reasons.sw_thermal_slowdown":         "clocks_throttle_reasons.sw_thermal_slowdown",
		"clocks_throttle_reasons.sync_boost":                  "clocks_throttle_reasons.sync_boost",
		"memory.total":                                        "memory.total [MiB]",
		"memory.used":                                         "memory.used [MiB]",
		"memory.free":                                         "memory.free [MiB]",
		"compute_mode":                                        "compute_mode",
		"utilization.gpu":                                     "utilization.gpu [%]",
		"utilization.memory":                                  "utilization.memory [%]",
		"encoder.stats.sessionCount":                          "encoder.stats.sessionCount",
		"encoder.stats.averageFps":                            "encoder.stats.averageFps",
		"encoder.stats.averageLatency":                        "encoder.stats.averageLatency",
		"ecc.mode.current":                                    "ecc.mode.current",
		"ecc.mode.pending":                                    "ecc.mode.pending",
		"ecc.errors.corrected.volatile.device_memory":         "ecc.errors.corrected.volatile.device_memory",
		"ecc.errors.corrected.volatile.dram":                  "ecc.errors.corrected.volatile.dram",
		"ecc.errors.corrected.volatile.register_file":         "ecc.errors.corrected.volatile.register_file",
		"ecc.errors.corrected.volatile.l1_cache":              "ecc.errors.corrected.volatile.l1_cache",
		"ecc.errors.corrected.volatile.l2_cache":              "ecc.errors.corrected.volatile.l2_cache",
		"ecc.errors.corrected.volatile.texture_memory":        "ecc.errors.corrected.volatile.texture_memory",
		"ecc.errors.corrected.volatile.cbu":                   "ecc.errors.corrected.volatile.cbu",
		"ecc.errors.corrected.volatile.sram":                  "ecc.errors.corrected.volatile.sram",
		"ecc.errors.corrected.volatile.total":                 "ecc.errors.corrected.volatile.total",
		"ecc.errors.corrected.aggregate.device_memory":        "ecc.errors.corrected.aggregate.device_memory",
		"ecc.errors.corrected.aggregate.dram":                 "ecc.errors.corrected.aggregate.dram",
		"ecc.errors.corrected.aggregate.register_file":        "ecc.errors.corrected.aggregate.register_file",
		"ecc.errors.corrected.aggregate.l1_cache":             "ecc.errors.corrected.aggregate.l1_cache",
		"ecc.errors.corrected.aggregate.l2_cache":             "ecc.errors.corrected.aggregate.l2_cache",
		"ecc.errors.corrected.aggregate.texture_memory":       "ecc.errors.corrected.aggregate.texture_memory",
		"ecc.errors.corrected.aggregate.cbu":                  "ecc.errors.corrected.aggregate.cbu",
		"ecc.errors.corrected.aggregate.sram":                 "ecc.errors.corrected.aggregate.sram",
		"ecc.errors.corrected.aggregate.total":                "ecc.errors.corrected.aggregate.total",
		"ecc.errors.uncorrected.volatile.device_memory":       "ecc.errors.uncorrected.volatile.device_memory",
		"ecc.errors.uncorrected.volatile.dram":                "ecc.errors.uncorrected.volatile.dram",
		"ecc.errors.uncorrected.volatile.register_file":       "ecc.errors.uncorrected.volatile.register_file",
		"ecc.errors.uncorrected.volatile.l1_cache":            "ecc.errors.uncorrected.volatile.l1_cache",
		"ecc.errors.uncorrected.volatile.l2_cache":            "ecc.errors.uncorrected.volatile.l2_cache",
		"ecc.errors.uncorrected.volatile.texture_memory":      "ecc.errors.uncorrected.volatile.texture_memory",
		"ecc.errors.uncorrected.volatile.cbu":                 "ecc.errors.uncorrected.volatile.cbu",
		"ecc.errors.uncorrected.volatile.sram":                "ecc.errors.uncorrected.volatile.sram",
		"ecc.errors.uncorrected.volatile.total":               "ecc.errors.uncorrected.volatile.total",
		"ecc.errors.uncorrected.aggregate.device_memory":      "ecc.errors.uncorrected.aggregate.device_memory",
		"ecc.errors.uncorrected.aggregate.dram":               "ecc.errors.uncorrected.aggregate.dram",
		"ecc.errors.uncorrected.aggregate.register_file":      "ecc.errors.uncorrected.aggregate.register_file",
		"ecc.errors.uncorrected.aggregate.l1_cache":           "ecc.errors.uncorrected.aggregate.l1_cache",
		"ecc.errors.uncorrected.aggregate.l2_cache":           "ecc.errors.uncorrected.aggregate.l2_cache",
		"ecc.errors.uncorrected.aggregate.texture_memory":     "ecc.errors.uncorrected.aggregate.texture_memory",
		"ecc.errors.uncorrected.aggregate.cbu":                "ecc.errors.uncorrected.aggregate.cbu",
		"ecc.errors.uncorrected.aggregate.sram":               "ecc.errors.uncorrected.aggregate.sram",
		"ecc.errors.uncorrected.aggregate.total":              "ecc.errors.uncorrected.aggregate.total",
		"retired_pages.single_bit_ecc.count":                  "retired_pages.single_bit_ecc.count",
		"retired_pages.double_bit.count":                      "retired_pages.double_bit.count",
		"retired_pages.pending":                               "retired_pages.pending",
		"temperature.gpu":                                     "temperature.gpu",
		"temperature.memory":                                  "temperature.memory",
		"power.management":                                    "power.management",
		"power.draw":                                          "power.draw [W]",
		"power.limit":                                         "power.limit [W]",
		"enforced.power.limit":                                "enforced.power.limit [W]",
		"power.default_limit":                                 "power.default_limit [W]",
		"power.min_limit":                                     "power.min_limit [W]",
		"power.max_limit":                                     "power.max_limit [W]",
		"clocks.current.graphics":                             "clocks.current.graphics [MHz]",
		"clocks.current.sm":                                   "clocks.current.sm [MHz]",
		"clocks.current.memory":                               "clocks.current.memory [MHz]",
		"clocks.current.video":                                "clocks.current.video [MHz]",
		"clocks.applications.graphics":                        "clocks.applications.graphics [MHz]",
		"clocks.applications.memory":                          "clocks.applications.memory [MHz]",
		"clocks.default_applications.graphics":                "clocks.default_applications.graphics [MHz]",
		"clocks.default_applications.memory":                  "clocks.default_applications.memory [MHz]",
		"clocks.max.graphics":                                 "clocks.max.graphics [MHz]",
		"clocks.max.sm":                                       "clocks.max.sm [MHz]",
		"clocks.max.memory":                                   "clocks.max.memory [MHz]",
		"mig.mode.current":                                    "mig.mode.current",
		"mig.mode.pending":                                    "mig.mode.pending",
	}
	// chipListCache []HuaWeiAIChip
	// dmgr          *devmanager.DeviceManager
)

const (
	uuidQField               QField = "uuid"
	nameQField               QField = "name"
	driverModelCurrentQField QField = "driver_model.current"
	driverModelPendingQField QField = "driver_model.pending"
	vBiosVersionQField       QField = "vbios_version"
	driverVersionQField      QField = "driver_version"
	qFieldsAuto                     = "AUTO"
	DefaultQField                   = qFieldsAuto
	hexToDecimalBase                = 16
	hexToDecimalUIntBitSize         = 64
	floatBitSize                    = 64
)

type runCmd func(cmd *exec.Cmd) error

// QField stands for query field - the field name before the query.
type QField string

type MetricInfo struct {
	desc            *prometheus.Desc
	MType           prometheus.ValueType
	ValueMultiplier float64
}

/*
1. 定义GPU信息收集器,gpuType可选：huawei、nvidia、moore
2. 确认是否启用GPU信息收集器
*/
type GpuInfoCollector struct {
	enable         bool
	gpuType        string
	nvidiaExporter *NvidiaExporter
}

type NvidiaExporter struct {
	mutex                 sync.RWMutex
	prefix                string
	qFields               []QField
	qFieldToMetricInfoMap map[QField]MetricInfo
	nvidiaSmiCommand      string
	failedScrapesTotal    prometheus.Counter
	exitCode              prometheus.Gauge
	gpuInfoDesc           *prometheus.Desc
	Command               runCmd
	ctx                   context.Context //nolint:containedctx
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
			nvidiaSmiCommand := jsonGpuCollectInfo.GetString("nvidiaSmiCommand")
			prefix := jsonGpuCollectInfo.GetString("nvidiaPrefix")
			// //如果采集华为GPU，则需要初始化collector获取芯片列表
			// if gpuType == "huawei" {
			// 	dmgr, err := devmanager.AutoInit("")
			// 	if err != nil {
			// 		huaweiLog.Errorf("new npu collector failed, error is %v", err)
			// 		return &GpuInfoCollector{
			// 			enable: false,
			// 		}, err
			// 	}
			// 	huaweiLog.Infof("npu exporter starting and the version is %s", versions.BuildVersion)
			// 	deviceParser := container.MakeDevicesParser(readCntMonitoringFlags())
			// 	defer deviceParser.Close()
			// 	if err := deviceParser.Init(); err != nil {
			// 		huaweiLog.Errorf("failed to init devices parser: %v", err)
			// 	}
			// 	CommonCollector := &NpuCollector{
			// 		cache:         cache.New(128),
			// 		cacheTime:     65 * time.Second,
			// 		updateTime:    60 * time.Second,
			// 		devicesParser: deviceParser,
			// 		Dmgr:          dmgr,
			// 	}
			// 	chipListCache = getChipListCache(*CommonCollector)
			// }
			//若采集NVIDIA GPU，则需要初始化nvidia-exporter
			if gpuType == "nvidia" {
				ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
				defer cancel()
				qFieldsOrdered, qFieldToRFieldMap, err := buildQFieldToRFieldMap(
					logger,
					DefaultQField,
					nvidiaSmiCommand,
					defaultRunCmd,
				)
				if err != nil {
					logger.Log("failed to build query field to returned field map", err)
					return &GpuInfoCollector{
						enable: false,
					}, nil
				}
				qFieldToMetricInfoMap := BuildQFieldToMetricInfoMap(prefix, qFieldToRFieldMap, logger)
				infoLabels := getLabels(requiredFields)
				nvidiaExporter := &NvidiaExporter{
					ctx:                   ctx,
					nvidiaSmiCommand:      nvidiaSmiCommand,
					qFields:               qFieldsOrdered,
					qFieldToMetricInfoMap: qFieldToMetricInfoMap,
					prefix:                prefix,
					failedScrapesTotal: prometheus.NewCounter(prometheus.CounterOpts{
						Namespace: prefix,
						Name:      "failed_scrapes_total",
						Help:      "Number of failed scrapes",
					}),
					exitCode: prometheus.NewGauge(prometheus.GaugeOpts{
						Namespace: prefix,
						Name:      "command_exit_code",
						Help:      "Exit code of the last scrape command",
					}),
					gpuInfoDesc: prometheus.NewDesc(
						prometheus.BuildFQName(prefix, "", "gpu_info"),
						fmt.Sprintf("A metric with a constant '1' value labeled by gpu %s.",
							strings.Join(infoLabels, ", ")),
						infoLabels,
						nil),
					Command: defaultRunCmd,
				}
				return &GpuInfoCollector{
					enable:         enable,
					gpuType:        gpuType,
					nvidiaExporter: nvidiaExporter,
				}, nil
			}
			return &GpuInfoCollector{
				enable:  enable,
				gpuType: gpuType,
			}, nil
		}
	}
}

func getLabels(reqFields []requiredField) []string {
	r := make([]string, len(reqFields))
	for i, reqField := range reqFields {
		r[i] = reqField.label
	}

	return r
}

func BuildQFieldToMetricInfoMap(
	prefix string,
	qFieldtoRFieldMap map[QField]RField,
	logger log.Logger,
) map[QField]MetricInfo {
	result := make(map[QField]MetricInfo)
	for qField, rField := range qFieldtoRFieldMap {
		result[qField] = BuildMetricInfo(prefix, rField, logger)
	}

	return result
}

func BuildMetricInfo(prefix string, rField RField, logger log.Logger) MetricInfo {
	fqName, multiplier := BuildFQNameAndMultiplier(prefix, rField, logger)
	desc := prometheus.NewDesc(fqName, string(rField), []string{"uuid"}, nil)

	return MetricInfo{
		desc:            desc,
		MType:           prometheus.GaugeValue,
		ValueMultiplier: multiplier,
	}
}

func ToSnakeCase(str string) string {
	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")

	return strings.ToLower(snake)
}

func BuildFQNameAndMultiplier(prefix string, rField RField, logger log.Logger) (string, float64) {
	rFieldStr := string(rField)
	suffixTransformed := rFieldStr
	multiplier := 1.0
	split := strings.Split(rFieldStr, " ")[0]

	switch {
	case strings.HasSuffix(rFieldStr, " [W]"):
		suffixTransformed = split + "_watts"
	case strings.HasSuffix(rFieldStr, " [MHz]"):
		suffixTransformed = split + "_clock_hz"
		multiplier = 1000000
	case strings.HasSuffix(rFieldStr, " [MiB]"):
		suffixTransformed = split + "_bytes"
		multiplier = 1048576
	case strings.HasSuffix(rFieldStr, " [%]"):
		suffixTransformed = split + "_ratio"
		multiplier = 0.01
	case strings.HasSuffix(rFieldStr, " [us]"):
		suffixTransformed = split + "_seconds"
		multiplier = 0.000001
	}

	suffixTransformed = strings.ReplaceAll(suffixTransformed, ".", "_")
	suffixTransformed = ToSnakeCase(suffixTransformed)

	if strings.ContainsAny(suffixTransformed, " []") {
		suffixTransformed = strings.ReplaceAll(suffixTransformed, " [", "_")
		suffixTransformed = strings.ReplaceAll(suffixTransformed, "]", "")

		logger.Log("returned field contains unexpected characters, "+
			"it is parsed it with best effort, but it might get renamed in the future. "+
			"please report it in the project's issue tracker",
			"rfield_name", rFieldStr,
			"parsed_name", suffixTransformed,
		)
	}

	fqName := prometheus.BuildFQName(prefix, "", suffixTransformed)

	return fqName, multiplier
}

func toQFieldSlice(ss []string) []QField {
	r := make([]QField, len(ss))
	for i, s := range ss {
		r[i] = QField(s)
	}

	return r
}

func removeDuplicates[T comparable](qFields []T) []T {
	valMap := make(map[T]struct{})

	var uniques []T

	for _, field := range qFields {
		_, exists := valMap[field]
		if !exists {
			uniques = append(uniques, field)
			valMap[field] = struct{}{}
		}
	}

	return uniques
}

func ParseAutoQFields(nvidiaSmiCommand string, command runCmd) ([]QField, error) {
	cmdAndArgs := strings.Fields(nvidiaSmiCommand)
	cmdAndArgs = append(cmdAndArgs, "--help-query-gpu")
	cmd := exec.Command(cmdAndArgs[0], cmdAndArgs[1:]...) //nolint:gosec

	var stdout bytes.Buffer

	var stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := command(cmd)

	outStr := stdout.String()
	errStr := stderr.String()

	exitCode := -1

	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		exitCode = exitError.ExitCode()
	}

	if err != nil {
		return nil, fmt.Errorf(
			"command failed: code: %d | command: %q | stdout: %q | stderr: %q: %w",
			exitCode,
			strings.Join(cmdAndArgs, " "),
			outStr,
			errStr,
			err,
		)
	}

	fields := ExtractQFields(outStr)
	if fields == nil {
		return nil, fmt.Errorf(
			"could not extract any query fields: code: %d | command: %q | stdout: %q | stderr: %q",
			exitCode,
			strings.Join(cmdAndArgs, " "),
			outStr,
			errStr,
		)
	}

	return fields, nil
}

func ExtractQFields(text string) []QField {
	found := fieldRegex.FindAllStringSubmatch(text, -1)

	fields := make([]QField, len(found))
	for i, ss := range found {
		fields[i] = QField(ss[1])
	}

	return fields
}

func buildQFieldToRFieldMap(logger log.Logger, qFieldsRaw string, nvidiaSmiCommand string,
	command runCmd,
) ([]QField, map[QField]RField, error) {
	qFieldsSeparated := strings.Split(qFieldsRaw, ",")

	qFields := toQFieldSlice(qFieldsSeparated)
	for _, reqField := range requiredFields {
		qFields = append(qFields, reqField.qField)
	}

	qFields = removeDuplicates(qFields)

	if len(qFieldsSeparated) == 1 && qFieldsSeparated[0] == qFieldsAuto {
		parsed, err := ParseAutoQFields(nvidiaSmiCommand, command)
		if err != nil {
			logger.Log("failed to auto-determine query field names, falling back to the built-in list", err)

			keys := slices.Collect(maps.Keys(fallbackQFieldToRFieldMap))

			return keys, fallbackQFieldToRFieldMap, nil
		}

		qFields = parsed
	}

	_, resultTable, err := scrape(qFields, nvidiaSmiCommand, command)

	var rFields []RField

	if err != nil {
		logger.Log(
			"failed to run the initial scrape, using the built-in list for field mapping",
			"err",
			err,
		)

		rFields, err = getFallbackValues(qFields)
		if err != nil {
			return nil, nil, err
		}
	} else {
		rFields = resultTable.RFields
	}

	r := make(map[QField]RField, len(qFields))
	for i, q := range qFields {
		r[q] = rFields[i]
	}

	return qFields, r, nil
}

func getFallbackValues(qFields []QField) ([]RField, error) {
	rFields := make([]RField, len(qFields))

	counter := 0

	for _, q := range qFields {
		val, contains := fallbackQFieldToRFieldMap[q]
		if !contains {
			return nil, fmt.Errorf("unexpected query field: %q", q)
		}

		rFields[counter] = val
		counter++
	}

	return rFields, nil
}

// func readCntMonitoringFlags() container.CntNpuMonitorOpts {
// 	opts := container.CntNpuMonitorOpts{UserBackUp: true}
// 	switch containerMode {
// 	case containerModeDocker:
// 		opts.EndpointType = container.EndpointTypeDockerd
// 		opts.OciEndpoint = container.DefaultDockerAddr
// 		opts.CriEndpoint = container.DefaultDockerShim
// 	case containerModeContainerd:
// 		opts.EndpointType = container.EndpointTypeContainerd
// 		opts.OciEndpoint = container.DefaultContainerdAddr
// 		opts.CriEndpoint = container.DefaultContainerdAddr
// 	case containerModeIsula:
// 		opts.EndpointType = container.EndpointTypeIsula
// 		opts.OciEndpoint = container.DefaultIsuladAddr
// 		opts.CriEndpoint = container.DefaultIsuladAddr
// 	default:
// 		hwlog.RunLog.Error("invalid container mode setting,reset to docker")
// 		opts.EndpointType = container.EndpointTypeDockerd
// 		opts.OciEndpoint = container.DefaultDockerAddr
// 		opts.CriEndpoint = container.DefaultDockerShim
// 	}
// 	if containerd != "" {
// 		opts.OciEndpoint = containerd
// 		opts.UserBackUp = false
// 	}
// 	if endpoint != "" {
// 		opts.CriEndpoint = endpoint
// 		opts.UserBackUp = false
// 	}
// 	return opts
// }

func (collector *GpuInfoCollector) Update(ch chan<- prometheus.Metric) error {
	if collector.enable {
		if collector.gpuType == "huawei" {
			// metrics := collectHuaweiMetric()
			// for _, metric := range metrics {
			// 	ch <- metric
			// }
		} else if collector.gpuType == "nvidia" {
			// metrics := collectNvidiaMetric()
			// for _, metric := range metrics {
			// 	ch <- metric
			// }
			collector.nvidiaExporter.mutex.Lock()
			defer collector.nvidiaExporter.mutex.Unlock()

			exitCode, currentTable, err := scrape(collector.nvidiaExporter.qFields, collector.nvidiaExporter.nvidiaSmiCommand, collector.nvidiaExporter.Command)
			collector.nvidiaExporter.exitCode.Set(float64(exitCode))

			collector.nvidiaExporter.sendMetric(ch, collector.nvidiaExporter.exitCode)

			if err != nil {
				logger.Log("failed to collect metrics", "err", err)

				ch <- collector.nvidiaExporter.failedScrapesTotal
				collector.nvidiaExporter.failedScrapesTotal.Inc()

				return err
			}

			for _, currentRow := range currentTable.Rows {
				uuid := strings.TrimPrefix(
					strings.ToLower(currentRow.QFieldToCells[uuidQField].RawValue),
					"gpu-",
				)
				name := currentRow.QFieldToCells[nameQField].RawValue
				driverModelCurrent := currentRow.QFieldToCells[driverModelCurrentQField].RawValue
				driverModelPending := currentRow.QFieldToCells[driverModelPendingQField].RawValue
				vBiosVersion := currentRow.QFieldToCells[vBiosVersionQField].RawValue
				driverVersion := currentRow.QFieldToCells[driverVersionQField].RawValue

				infoMetric, infoMetricErr := prometheus.NewConstMetric(collector.nvidiaExporter.gpuInfoDesc, prometheus.GaugeValue,
					1, uuid, name, driverModelCurrent,
					driverModelPending, vBiosVersion, driverVersion)
				if infoMetricErr != nil {
					logger.Log("failed to create info metric", "err", infoMetricErr)

					continue
				}

				collector.nvidiaExporter.sendMetric(ch, infoMetric)

				for _, currentCell := range currentRow.Cells {
					metricInfo := collector.nvidiaExporter.qFieldToMetricInfoMap[currentCell.QField]

					num, numErr := TransformRawValue(currentCell.RawValue, metricInfo.ValueMultiplier)
					if numErr != nil {
						logger.Log("failed to transform raw value", "err", numErr, "query_field_name",
							currentCell.QField, "raw_value", currentCell.RawValue)

						continue
					}

					metric, metricErr := prometheus.NewConstMetric(
						metricInfo.desc,
						metricInfo.MType,
						num,
						uuid,
					)
					if metricErr != nil {
						logger.Log("failed to create metric", "err", metricErr, "query_field_name",
							currentCell.QField, "raw_value", currentCell.RawValue)

						continue
					}

					collector.nvidiaExporter.sendMetric(ch, metric)
				}
			}

		} else {
			logger.Log("GPU类型不支持:", collector.gpuType)
			return nil
		}
	}
	return nil
}

func HexToDecimal(hex string) (float64, error) {
	s := hex
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.ReplaceAll(s, "0X", "")
	parsed, err := strconv.ParseUint(s, hexToDecimalBase, hexToDecimalUIntBitSize)

	return float64(parsed), err
}

func TransformRawValue(rawValue string, valueMultiplier float64) (float64, error) {
	trimmed := strings.TrimSpace(rawValue)
	if strings.HasPrefix(trimmed, "0x") {
		decimal, err := HexToDecimal(trimmed)
		if err != nil {
			return 0, fmt.Errorf("failed to transform raw value %q: %w", trimmed, err)
		}

		return decimal, nil
	}

	val := strings.ToLower(trimmed)

	switch val {
	case "enabled", "yes", "active":
		return 1, nil
	case "disabled", "no", "not active":
		return 0, nil
	case "default":
		return 0, nil
	case "exclusive_thread":
		return 1, nil
	case "prohibited":
		return 2, nil
	case "exclusive_process":
		return 3, nil
	default:
		return parseSanitizedValueWithBestEffort(val, valueMultiplier)
	}
}

func parseSanitizedValueWithBestEffort(
	sanitizedValue string,
	valueMultiplier float64,
) (float64, error) {
	allNums := numericRegex.FindAllString(sanitizedValue, 2) //nolint:mnd
	if len(allNums) != 1 {
		return -1, fmt.Errorf("could not parse number from value: %q", sanitizedValue)
	}

	parsed, err := strconv.ParseFloat(allNums[0], floatBitSize)
	if err != nil {
		return -1, fmt.Errorf("failed to parse float %q: %w", allNums[0], err)
	}

	return parsed * valueMultiplier, nil
}

type Row struct {
	QFieldToCells map[QField]Cell
	Cells         []Cell
}

type Cell struct {
	QField   QField
	RField   RField
	RawValue string
}

// RField stands for returned field - the field name as returned by the nvidia-smi.
type RField string

type Table struct {
	Rows          []Row
	RFields       []RField
	QFieldToCells map[QField][]Cell
}

func QFieldSliceToStringSlice(qs []QField) []string {
	r := make([]string, len(qs))
	for i, q := range qs {
		r[i] = string(q)
	}

	return r
}

func scrape(qFields []QField, nvidiaSmiCommand string, command runCmd) (int, *Table, error) {
	qFieldsJoined := strings.Join(QFieldSliceToStringSlice(qFields), ",")

	cmdAndArgs := strings.Fields(nvidiaSmiCommand)
	cmdAndArgs = append(cmdAndArgs, "--query-gpu="+qFieldsJoined)
	cmdAndArgs = append(cmdAndArgs, "--format=csv")

	var stdout bytes.Buffer

	var stderr bytes.Buffer

	cmd := exec.Command(cmdAndArgs[0], cmdAndArgs[1:]...) //nolint:gosec
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := command(cmd)
	if err != nil {
		exitCode := -1

		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			exitCode = exitError.ExitCode()
		}

		return exitCode, nil, fmt.Errorf(
			"command failed: code: %d | command: %s | stdout: %s | stderr: %s: %w",
			exitCode,
			strings.Join(cmdAndArgs, " "),
			stdout.String(),
			stderr.String(),
			err,
		)
	}

	t, err := ParseCSVIntoTable(strings.TrimSpace(stdout.String()), qFields)
	if err != nil {
		return -1, nil, err
	}

	return 0, &t, nil
}

func toRFieldSlice(ss []string) []RField {
	r := make([]RField, len(ss))
	for i, s := range ss {
		r[i] = RField(s)
	}

	return r
}

func ParseCSVIntoTable(queryResult string, qFields []QField) (Table, error) {
	lines := strings.Split(strings.TrimSpace(queryResult), "\n")
	titlesLine := lines[0]
	valuesLines := lines[1:]
	rFields := toRFieldSlice(parseCSVLine(titlesLine))

	numCols := len(qFields)
	numRows := len(valuesLines)

	rows := make([]Row, numRows)

	qFieldToCells := make(map[QField][]Cell)
	for _, q := range qFields {
		qFieldToCells[q] = make([]Cell, numRows)
	}

	for rowIndex, valuesLine := range valuesLines {
		qFieldToCell := make(map[QField]Cell, numCols)
		cells := make([]Cell, numCols)
		rawValues := parseCSVLine(valuesLine)

		if len(qFields) != len(rFields) {
			return Table{}, fmt.Errorf(
				"field count mismatch: query fields: %d, returned fields: %d",
				len(qFields),
				len(rFields),
			)
		}

		for colIndex, rawValue := range rawValues {
			currentQField := qFields[colIndex]
			currentRField := rFields[colIndex]
			tableCell := Cell{
				QField:   currentQField,
				RField:   currentRField,
				RawValue: rawValue,
			}
			qFieldToCell[currentQField] = tableCell
			cells[colIndex] = tableCell
			qFieldToCells[currentQField][rowIndex] = tableCell
		}

		tableRow := Row{
			QFieldToCells: qFieldToCell,
			Cells:         cells,
		}

		rows[rowIndex] = tableRow
	}

	return Table{
		Rows:          rows,
		RFields:       rFields,
		QFieldToCells: qFieldToCells,
	}, nil
}

func parseCSVLine(line string) []string {
	values := strings.Split(line, ",")
	result := make([]string, len(values))

	for i, field := range values {
		result[i] = strings.TrimSpace(field)
	}

	return result
}

func (e *NvidiaExporter) sendMetric(ch chan<- prometheus.Metric, metric prometheus.Metric) {
	select {
	case <-e.ctx.Done():
		logger.Log("context done, return")

		return
	case ch <- metric:
	}
}

// func collectHuaweiMetric() []prometheus.Metric {
// 	var metrics []prometheus.Metric
// 	i := 0
// 	//获取每一张卡的信息
// 	for _, chip := range chipListCache {
// 		hbmInfo, err := dmgr.GetDeviceHbmInfo(chip.LogicID)
// 		if err != nil {
// 			huaweiLog.Errorf("get npu hbm info failed, err is : %v", err)
// 		}
// 		memoryUsedMetric := creatMemoryMetric(strconv.Itoa(i), chip.VDieID, strconv.FormatUint(hbmInfo.MemorySize, 10), float64(hbmInfo.Usage))
// 		metrics = append(metrics, memoryUsedMetric)
// 		i++
// 	}
// 	return metrics
// }

// func collectNvidiaMetric() []prometheus.Metric {
// 	ret := nvml.Init()
// 	if ret != nvml.SUCCESS {
// 		nvidiaLog.Fatalf("Unable to initialize NVML: %v", nvml.ErrorString(ret))
// 	}
// 	defer func() {
// 		ret := nvml.Shutdown()
// 		if ret != nvml.SUCCESS {
// 			nvidiaLog.Fatalf("Unable to shutdown NVML: %v", nvml.ErrorString(ret))
// 		}
// 	}()

// 	count, ret := nvml.DeviceGetCount()
// 	if ret != nvml.SUCCESS {
// 		nvidiaLog.Fatalf("Unable to get device count: %v", nvml.ErrorString(ret))
// 	}

// 	var metrics []prometheus.Metric

// 	//遍历每一个GPU卡
// 	for i := 0; i < count; i++ {
// 		device, ret := nvml.DeviceGetHandleByIndex(i)
// 		if ret != nvml.SUCCESS {
// 			nvidiaLog.Fatalf("Unable to get device at index %d: %v", i, nvml.ErrorString(ret))
// 		}

// 		uuid, ret := device.GetUUID()
// 		if ret != nvml.SUCCESS {
// 			nvidiaLog.Fatalf("Unable to get uuid of device at index %d: %v", i, nvml.ErrorString(ret))
// 		}

// 		utilization, ret := device.GetUtilizationRates()
// 		if ret != nvml.SUCCESS {
// 			nvidiaLog.Fatalf("Unable to get utilization of device at index %d: %v", i, nvml.ErrorString(ret))
// 		}

// 		memory, ret := device.GetMemoryInfo()
// 		if ret != nvml.SUCCESS {
// 			nvidiaLog.Fatalf("Unable to get memory of device at index %d: %v", i, nvml.ErrorString(ret))
// 		}

// 		gpuUtilizationMetric := createGpuUtilizationMetric(strconv.Itoa(i), uuid, float64(utilization.Gpu))
// 		memoryUtilizationMetric := creatMemoryUtilizationMetric(strconv.Itoa(i), uuid, float64(utilization.Memory))
// 		memoryUsedMetric := creatMemoryMetric(strconv.Itoa(i), uuid, strconv.FormatUint(memory.Total, 10), float64(memory.Used))

// 		metrics = append(metrics, gpuUtilizationMetric, memoryUtilizationMetric, memoryUsedMetric)
// 	}
// 	return metrics
// }

// // NpuCollector for collect metrics
// type NpuCollector struct {
// 	cache         *cache.ConcurrencyLRUCache
// 	devicesParser *container.DevicesParser
// 	updateTime    time.Duration
// 	cacheTime     time.Duration
// 	Dmgr          *devmanager.DeviceManager
// }

// // HuaWeiAIChip chip info
// type HuaWeiAIChip struct {

// 	// CardId npu card id
// 	CardId int32 `json:"card_id"`
// 	// PhyId npu chip phy id
// 	PhyId int32 `json:"phy_id"`
// 	// DeviceID the chip physic ID
// 	DeviceID int32 `json:"device_id"`
// 	// the chip logic ID
// 	LogicID int32 `json:"logic_id"`
// 	// VDieID the vdie id
// 	VDieID string `json:"vdie_id"`
// 	// MainBoardId main board id , used to distinguish between A900A3SuperPod and A9000A3SuperPod
// 	MainBoardId uint32
// 	// ChipInfo the chip info
// 	ChipInfo *common.ChipInfo `json:"chip_info"`
// 	// BoardInfo board info of device, but not display
// 	BoardInfo *common.BoardInfo

// 	// VDevActivityInfo the activity virtual device info
// 	VDevActivityInfo *common.VDevActivityInfo `json:"v_dev_activity_info"`
// 	// VDevInfos the virtual device info
// 	VDevInfos *common.VirtualDevInfo `json:"v_dev_infos"`
// 	// PCIeBusInfo bus info
// 	PCIeBusInfo string
// }

// func getChipListCache(n NpuCollector) []HuaWeiAIChip {
// 	obj, err := n.cache.Get("npu-exporter-npu-list")
// 	if err != nil {
// 		huaweiLog.Errorf("get npu chip list from cache failed,err is : %v", err)
// 		return make([]HuaWeiAIChip, 0)
// 	}
// 	if obj == nil {
// 		huaweiLog.LogfWithOptions(huaweiLog.ErrorLevel, huaweiLog.LogOptions{Domain: "getChipListCache"},
// 			"there is no chip list info in cache,please check collect logs")
// 		return make([]HuaWeiAIChip, 0)
// 	}

// 	chipList, ok := obj.([]HuaWeiAIChip)
// 	if !ok {
// 		huaweiLog.Errorf("error npu chip info cache and convert failed,real type is (%T)", obj)
// 		n.cache.Delete("npu-exporter-npu-list")
// 		return make([]HuaWeiAIChip, 0)
// 	}
// 	// if cache is empty or nil, return empty list
// 	if len(chipList) == 0 {
// 		return make([]HuaWeiAIChip, 0)
// 	}
// 	return chipList
// }

// /*
// 生成GPU利用率指标
// */
// func createGpuUtilizationMetric(id string, uuid string, utilization float64) prometheus.Metric {
// 	gpuUtilization := promauto.NewGaugeVec(
// 		prometheus.GaugeOpts{
// 			Name: "gpu_utilization",
// 			Help: "Percent of time over the past sample period during which one or more kernels was executing on the GPU.",
// 		},
// 		[]string{"id", "uuid"},
// 	)
// 	gpuUtilizationMetric := gpuUtilization.WithLabelValues(id, uuid)
// 	gpuUtilizationMetric.Set(utilization)
// 	return gpuUtilizationMetric
// }

// /*
// 生成memory利用率指标
// */
// func creatMemoryUtilizationMetric(id string, uuid string, utilization float64) prometheus.Metric {
// 	memoryUtilization := promauto.NewGaugeVec(
// 		prometheus.GaugeOpts{
// 			Name: "memory_utilization",
// 			Help: "Percent of time over the past sample period during which global (device) memory was being read or written.",
// 		},
// 		[]string{"id", "uuid"},
// 	)
// 	memoryUtilizationMetric := memoryUtilization.WithLabelValues(id, uuid)
// 	memoryUtilizationMetric.Set(utilization)
// 	return memoryUtilizationMetric
// }

// /*
// 生成memory使用及总量指标
// */
// func creatMemoryMetric(id string, uuid string, total string, utilization float64) prometheus.Metric {
// 	memoryUsed := promauto.NewGaugeVec(
// 		prometheus.GaugeOpts{
// 			Name: "gpu_used_memory",
// 			Help: "Sum of Reserved and Allocated device memory (in bytes). Note that the driver/GPU always sets aside a small amount of memory for bookkeeping ",
// 		},
// 		[]string{"id", "uuid", "total"},
// 	)
// 	memoryUsedMetric := memoryUsed.WithLabelValues(id, uuid, total)
// 	memoryUsedMetric.Set(utilization)
// 	return memoryUsedMetric
// }
