package collector

import (
	// "ascend-common/common-utils/cache"
	// "ascend-common/common-utils/hwlog"
	// "ascend-common/devmanager"
	// "ascend-common/devmanager/common"

	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	// huaweiLog "github.com/chaolihf/node_exporter/collector/huawei-utils/logger"
	// versions "github.com/chaolihf/node_exporter/collector/huawei-versions"

	// "github.com/chaolihf/node_exporter/collector/huawei-collector/container"

	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
)

func init() {
	registerCollector("gpu", true, newGpuInfoCollector)
}

// type requiredField struct {
// 	qField QField
// 	label  string
// }

// GPU 指标的结构体
type GPUMetrics struct {
	Index             string
	UUID              string
	GPUUtilization    float64
	MemoryUtilization float64
	MemoryTotal       float64
	MemoryUsed        float64
}

/*
1. 定义GPU信息收集器,gpuType可选：huawei、nvidia、moore
2. 确认是否启用GPU信息收集器
*/
type GpuInfoCollector struct {
	enable  bool
	gpuType string
	url     string
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
			url := jsonGpuCollectInfo.GetString("url")
			// prefix := jsonGpuCollectInfo.GetString("nvidiaPrefix")
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
			// if gpuType == "nvidia" {
			// 	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
			// 	defer cancel()
			// 	qFieldsOrdered, qFieldToRFieldMap, err := buildQFieldToRFieldMap(
			// 		logger,
			// 		DefaultQField,
			// 		nvidiaSmiCommand,
			// 		defaultRunCmd,
			// 	)
			// 	if err != nil {
			// 		logger.Log("failed to build query field to returned field map", err)
			// 		return &GpuInfoCollector{
			// 			enable: false,
			// 		}, nil
			// 	}
			// 	qFieldToMetricInfoMap := BuildQFieldToMetricInfoMap(prefix, qFieldToRFieldMap, logger)
			// 	infoLabels := getLabels(requiredFields)
			// 	nvidiaExporter := &NvidiaExporter{
			// 		ctx:                   ctx,
			// 		nvidiaSmiCommand:      nvidiaSmiCommand,
			// 		qFields:               qFieldsOrdered,
			// 		qFieldToMetricInfoMap: qFieldToMetricInfoMap,
			// 		prefix:                prefix,
			// 		failedScrapesTotal: prometheus.NewCounter(prometheus.CounterOpts{
			// 			Namespace: prefix,
			// 			Name:      "failed_scrapes_total",
			// 			Help:      "Number of failed scrapes",
			// 		}),
			// 		exitCode: prometheus.NewGauge(prometheus.GaugeOpts{
			// 			Namespace: prefix,
			// 			Name:      "command_exit_code",
			// 			Help:      "Exit code of the last scrape command",
			// 		}),
			// 		gpuInfoDesc: prometheus.NewDesc(
			// 			prometheus.BuildFQName(prefix, "", "gpu_info"),
			// 			fmt.Sprintf("A metric with a constant '1' value labeled by gpu %s.",
			// 				strings.Join(infoLabels, ", ")),
			// 			infoLabels,
			// 			nil),
			// 		Command: defaultRunCmd,
			// 	}
			// 	return &GpuInfoCollector{
			// 		enable:         enable,
			// 		gpuType:        gpuType,
			// 	}, nil
			// }
			return &GpuInfoCollector{
				enable:  enable,
				gpuType: gpuType,
				url:     url,
			}, nil
		}
	}
}

// func getLabels(reqFields []requiredField) []string {
// 	r := make([]string, len(reqFields))
// 	for i, reqField := range reqFields {
// 		r[i] = reqField.label
// 	}

// 	return r
// }

// func BuildQFieldToMetricInfoMap(
// 	prefix string,
// 	qFieldtoRFieldMap map[QField]RField,
// 	logger log.Logger,
// ) map[QField]MetricInfo {
// 	result := make(map[QField]MetricInfo)
// 	for qField, rField := range qFieldtoRFieldMap {
// 		result[qField] = BuildMetricInfo(prefix, rField, logger)
// 	}

// 	return result
// }

// func BuildMetricInfo(prefix string, rField RField, logger log.Logger) MetricInfo {
// 	fqName, multiplier := BuildFQNameAndMultiplier(prefix, rField, logger)
// 	desc := prometheus.NewDesc(fqName, string(rField), []string{"uuid"}, nil)

// 	return MetricInfo{
// 		desc:            desc,
// 		MType:           prometheus.GaugeValue,
// 		ValueMultiplier: multiplier,
// 	}
// }

// func ToSnakeCase(str string) string {
// 	snake := matchFirstCap.ReplaceAllString(str, "${1}_${2}")
// 	snake = matchAllCap.ReplaceAllString(snake, "${1}_${2}")

// 	return strings.ToLower(snake)
// }

// func BuildFQNameAndMultiplier(prefix string, rField RField, logger log.Logger) (string, float64) {
// 	rFieldStr := string(rField)
// 	suffixTransformed := rFieldStr
// 	multiplier := 1.0
// 	split := strings.Split(rFieldStr, " ")[0]

// 	switch {
// 	case strings.HasSuffix(rFieldStr, " [W]"):
// 		suffixTransformed = split + "_watts"
// 	case strings.HasSuffix(rFieldStr, " [MHz]"):
// 		suffixTransformed = split + "_clock_hz"
// 		multiplier = 1000000
// 	case strings.HasSuffix(rFieldStr, " [MiB]"):
// 		suffixTransformed = split + "_bytes"
// 		multiplier = 1048576
// 	case strings.HasSuffix(rFieldStr, " [%]"):
// 		suffixTransformed = split + "_ratio"
// 		multiplier = 0.01
// 	case strings.HasSuffix(rFieldStr, " [us]"):
// 		suffixTransformed = split + "_seconds"
// 		multiplier = 0.000001
// 	}

// 	suffixTransformed = strings.ReplaceAll(suffixTransformed, ".", "_")
// 	suffixTransformed = ToSnakeCase(suffixTransformed)

// 	if strings.ContainsAny(suffixTransformed, " []") {
// 		suffixTransformed = strings.ReplaceAll(suffixTransformed, " [", "_")
// 		suffixTransformed = strings.ReplaceAll(suffixTransformed, "]", "")

// 		logger.Log("returned field contains unexpected characters, "+
// 			"it is parsed it with best effort, but it might get renamed in the future. "+
// 			"please report it in the project's issue tracker",
// 			"rfield_name", rFieldStr,
// 			"parsed_name", suffixTransformed,
// 		)
// 	}

// 	fqName := prometheus.BuildFQName(prefix, "", suffixTransformed)

// 	return fqName, multiplier
// }

// func toQFieldSlice(ss []string) []QField {
// 	r := make([]QField, len(ss))
// 	for i, s := range ss {
// 		r[i] = QField(s)
// 	}

// 	return r
// }

// func removeDuplicates[T comparable](qFields []T) []T {
// 	valMap := make(map[T]struct{})

// 	var uniques []T

// 	for _, field := range qFields {
// 		_, exists := valMap[field]
// 		if !exists {
// 			uniques = append(uniques, field)
// 			valMap[field] = struct{}{}
// 		}
// 	}

// 	return uniques
// }

// func ParseAutoQFields(nvidiaSmiCommand string, command runCmd) ([]QField, error) {
// 	cmdAndArgs := strings.Fields(nvidiaSmiCommand)
// 	cmdAndArgs = append(cmdAndArgs, "--help-query-gpu")
// 	cmd := exec.Command(cmdAndArgs[0], cmdAndArgs[1:]...) //nolint:gosec

// 	var stdout bytes.Buffer

// 	var stderr bytes.Buffer

// 	cmd.Stdout = &stdout
// 	cmd.Stderr = &stderr

// 	err := command(cmd)

// 	outStr := stdout.String()
// 	errStr := stderr.String()

// 	exitCode := -1

// 	var exitError *exec.ExitError
// 	if errors.As(err, &exitError) {
// 		exitCode = exitError.ExitCode()
// 	}

// 	if err != nil {
// 		return nil, fmt.Errorf(
// 			"command failed: code: %d | command: %q | stdout: %q | stderr: %q: %w",
// 			exitCode,
// 			strings.Join(cmdAndArgs, " "),
// 			outStr,
// 			errStr,
// 			err,
// 		)
// 	}

// 	fields := ExtractQFields(outStr)
// 	if fields == nil {
// 		return nil, fmt.Errorf(
// 			"could not extract any query fields: code: %d | command: %q | stdout: %q | stderr: %q",
// 			exitCode,
// 			strings.Join(cmdAndArgs, " "),
// 			outStr,
// 			errStr,
// 		)
// 	}

// 	return fields, nil
// }

// func ExtractQFields(text string) []QField {
// 	found := fieldRegex.FindAllStringSubmatch(text, -1)

// 	fields := make([]QField, len(found))
// 	for i, ss := range found {
// 		fields[i] = QField(ss[1])
// 	}

// 	return fields
// }

// func buildQFieldToRFieldMap(logger log.Logger, qFieldsRaw string, nvidiaSmiCommand string,
// 	command runCmd,
// ) ([]QField, map[QField]RField, error) {
// 	qFieldsSeparated := strings.Split(qFieldsRaw, ",")

// 	qFields := toQFieldSlice(qFieldsSeparated)
// 	for _, reqField := range requiredFields {
// 		qFields = append(qFields, reqField.qField)
// 	}

// 	qFields = removeDuplicates(qFields)

// 	if len(qFieldsSeparated) == 1 && qFieldsSeparated[0] == qFieldsAuto {
// 		parsed, err := ParseAutoQFields(nvidiaSmiCommand, command)
// 		if err != nil {
// 			logger.Log("failed to auto-determine query field names, falling back to the built-in list", err)

// 			keys := slices.Collect(maps.Keys(fallbackQFieldToRFieldMap))

// 			return keys, fallbackQFieldToRFieldMap, nil
// 		}

// 		qFields = parsed
// 	}

// 	_, resultTable, err := scrape(qFields, nvidiaSmiCommand, command)

// 	var rFields []RField

// 	if err != nil {
// 		logger.Log(
// 			"failed to run the initial scrape, using the built-in list for field mapping",
// 			"err",
// 			err,
// 		)

// 		rFields, err = getFallbackValues(qFields)
// 		if err != nil {
// 			return nil, nil, err
// 		}
// 	} else {
// 		rFields = resultTable.RFields
// 	}

// 	r := make(map[QField]RField, len(qFields))
// 	for i, q := range qFields {
// 		r[q] = rFields[i]
// 	}

// 	return qFields, r, nil
// }

// func getFallbackValues(qFields []QField) ([]RField, error) {
// 	rFields := make([]RField, len(qFields))

// 	counter := 0

// 	for _, q := range qFields {
// 		val, contains := fallbackQFieldToRFieldMap[q]
// 		if !contains {
// 			return nil, fmt.Errorf("unexpected query field: %q", q)
// 		}

// 		rFields[counter] = val
// 		counter++
// 	}

// 	return rFields, nil
// }

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

// 收集 GPU 指标
func (collector *GpuInfoCollector) collectGPUMetrics() ([]prometheus.Metric, error) {
	// 执行 nvidia-smi 命令
	cmd := exec.Command("nvidia-smi", "--query-gpu=index,uuid,utilization.gpu,utilization.memory,memory.total,memory.used", "--format=csv,noheader")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to execute nvidia-smi: %v", err)
	}

	// 存储所有生成的指标
	var metrics []prometheus.Metric

	// 创建指标描述符
	gpuUtilDesc := prometheus.NewDesc(
		"nvidia_gpu_utilization_ratio",
		"GPU utilization ratio (0.0 - 1.0)",
		[]string{"gpu_index", "gpu_uuid", "gpu_memory_total"},
		nil,
	)

	memUtilDesc := prometheus.NewDesc(
		"nvidia_gpu_memory_utilization_ratio",
		"GPU memory utilization ratio (0.0 - 1.0)",
		[]string{"gpu_index", "gpu_uuid", "gpu_memory_total"},
		nil,
	)

	memUsedDesc := prometheus.NewDesc(
		"nvidia_gpu_memory_used_bytes",
		"GPU memory used in bytes",
		[]string{"gpu_index", "gpu_uuid", "gpu_memory_total"},
		nil,
	)

	// 解析输出
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	for _, line := range lines {
		fields := strings.Split(strings.TrimSpace(line), ", ")
		if len(fields) != 6 {
			continue
		}

		index := fields[0]
		uuid := fields[1]

		memTotal, _ := strconv.ParseFloat(strings.TrimSuffix(fields[4], " MiB"), 64)
		memTotalBytes := strconv.FormatFloat(memTotal*1024*1024, 'f', -1, 64) // 转换为字节

		// 解析 GPU 使用率
		gpuUtil, err := strconv.ParseFloat(strings.TrimSuffix(fields[2], " %"), 64)
		if err == nil {
			metrics = append(metrics, prometheus.MustNewConstMetric(
				gpuUtilDesc,
				prometheus.GaugeValue,
				gpuUtil/100.0, // 转换为 0-1 的比率
				index,
				uuid,
				memTotalBytes, // GPU 总内存
			))
		}

		// 解析内存使用率
		memUtil, err := strconv.ParseFloat(strings.TrimSuffix(fields[3], " %"), 64)
		if err == nil {
			metrics = append(metrics, prometheus.MustNewConstMetric(
				memUtilDesc,
				prometheus.GaugeValue,
				memUtil/100.0, // 转换为 0-1 的比率
				index,
				uuid,
				memTotalBytes, // GPU 总内存
			))
		}

		// 解析已使用内存
		memUsed, err := strconv.ParseFloat(strings.TrimSuffix(fields[5], " MiB"), 64)
		if err == nil {
			metrics = append(metrics, prometheus.MustNewConstMetric(
				memUsedDesc,
				prometheus.GaugeValue,
				memUsed*1024*1024, // 转换为字节
				index,
				uuid,
				memTotalBytes, // GPU 总内存
			))
		}
	}

	return metrics, nil
}

func (collector *GpuInfoCollector) fetchMetrics() ([]prometheus.Metric, error) {
	// 发起 HTTP GET 请求
	resp, err := http.Get(collector.url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// 解析指标
	var parser expfmt.TextParser
	metricFamilies, err := parser.TextToMetricFamilies(strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics: %v", err)
	}

	// 转换为 prometheus.Metric 切片
	var metrics []prometheus.Metric
	for familyName, family := range metricFamilies {
		for _, m := range family.Metric {
			metric, err := convertToPrometheusMetric(familyName, family.GetType(), family.GetHelp(), m)
			if err != nil {
				fmt.Printf("Error converting metric %s: %v\n", familyName, err)
				continue
			}
			metrics = append(metrics, metric)
		}
	}

	return metrics, nil
}

func convertToPrometheusMetric(name string, metricType dto.MetricType, help string, metric *dto.Metric) (prometheus.Metric, error) {
	// 创建标签
	var labelNames []string
	var labelValues []string
	for _, label := range metric.Label {
		labelNames = append(labelNames, label.GetName())
		labelValues = append(labelValues, label.GetValue())
	}

	// 创建描述符
	desc := prometheus.NewDesc(
		name,
		help,
		labelNames,
		nil,
	)

	// 根据不同的指标类型创建相应的指标
	switch metricType {
	case dto.MetricType_COUNTER:
		return prometheus.NewConstMetric(
			desc,
			prometheus.CounterValue,
			metric.Counter.GetValue(),
			labelValues...,
		)

	case dto.MetricType_GAUGE:
		return prometheus.NewConstMetric(
			desc,
			prometheus.GaugeValue,
			metric.Gauge.GetValue(),
			labelValues...,
		)

	case dto.MetricType_HISTOGRAM:
		return prometheus.NewConstHistogram(
			desc,
			metric.Histogram.GetSampleCount(),
			metric.Histogram.GetSampleSum(),
			makeBuckets(metric.Histogram),
			labelValues...,
		)

	case dto.MetricType_SUMMARY:
		return prometheus.NewConstSummary(
			desc,
			metric.Summary.GetSampleCount(),
			metric.Summary.GetSampleSum(),
			makeQuantiles(metric.Summary),
			labelValues...,
		)

	default:
		return nil, fmt.Errorf("unsupported metric type: %v", metricType)
	}
}

func makeBuckets(h *dto.Histogram) map[float64]uint64 {
	buckets := make(map[float64]uint64, len(h.Bucket))
	for _, b := range h.Bucket {
		buckets[b.GetUpperBound()] = b.GetCumulativeCount()
	}
	return buckets
}

func makeQuantiles(s *dto.Summary) map[float64]float64 {
	quantiles := make(map[float64]float64, len(s.Quantile))
	for _, q := range s.Quantile {
		quantiles[q.GetQuantile()] = q.GetValue()
	}
	return quantiles
}

func (collector *GpuInfoCollector) Update(ch chan<- prometheus.Metric) error {
	if collector.enable {
		if collector.gpuType == "huawei" {
			// metrics := collectHuaweiMetric()
			// for _, metric := range metrics {
			// 	ch <- metric
			// }
			metrics, err := collector.fetchMetrics()
			if err != nil {
				return err
			}
			for _, metric := range metrics {
				ch <- metric
			}
		} else if collector.gpuType == "nvidia" {
			metrics, err := collector.collectGPUMetrics()
			if err != nil {
				return err
			} else {
				for _, metric := range metrics {
					ch <- metric
				}
			}
			// metrics := collectNvidiaMetric()
			// for _, metric := range metrics {
			// 	ch <- metric
			// }
			// collector.nvidiaExporter.mutex.Lock()
			// defer collector.nvidiaExporter.mutex.Unlock()

			// exitCode, currentTable, err := scrape(collector.nvidiaExporter.qFields, collector.nvidiaExporter.nvidiaSmiCommand, collector.nvidiaExporter.Command)
			// collector.nvidiaExporter.exitCode.Set(float64(exitCode))

			// collector.nvidiaExporter.sendMetric(ch, collector.nvidiaExporter.exitCode)

			// if err != nil {
			// 	logger.Log("failed to collect metrics", "err", err)

			// 	ch <- collector.nvidiaExporter.failedScrapesTotal
			// 	collector.nvidiaExporter.failedScrapesTotal.Inc()

			// 	return err
			// }

			// for _, currentRow := range currentTable.Rows {
			// 	uuid := strings.TrimPrefix(
			// 		strings.ToLower(currentRow.QFieldToCells[uuidQField].RawValue),
			// 		"gpu-",
			// 	)
			// 	name := currentRow.QFieldToCells[nameQField].RawValue
			// 	driverModelCurrent := currentRow.QFieldToCells[driverModelCurrentQField].RawValue
			// 	driverModelPending := currentRow.QFieldToCells[driverModelPendingQField].RawValue
			// 	vBiosVersion := currentRow.QFieldToCells[vBiosVersionQField].RawValue
			// 	driverVersion := currentRow.QFieldToCells[driverVersionQField].RawValue

			// 	infoMetric, infoMetricErr := prometheus.NewConstMetric(collector.nvidiaExporter.gpuInfoDesc, prometheus.GaugeValue,
			// 		1, uuid, name, driverModelCurrent,
			// 		driverModelPending, vBiosVersion, driverVersion)
			// 	if infoMetricErr != nil {
			// 		logger.Log("failed to create info metric", "err", infoMetricErr)

			// 		continue
			// 	}

			// 	collector.nvidiaExporter.sendMetric(ch, infoMetric)

			// 	for _, currentCell := range currentRow.Cells {
			// 		metricInfo := collector.nvidiaExporter.qFieldToMetricInfoMap[currentCell.QField]

			// 		num, numErr := TransformRawValue(currentCell.RawValue, metricInfo.ValueMultiplier)
			// 		if numErr != nil {
			// 			logger.Log("failed to transform raw value", "err", numErr, "query_field_name",
			// 				currentCell.QField, "raw_value", currentCell.RawValue)

			// 			continue
			// 		}

			// 		metric, metricErr := prometheus.NewConstMetric(
			// 			metricInfo.desc,
			// 			metricInfo.MType,
			// 			num,
			// 			uuid,
			// 		)
			// 		if metricErr != nil {
			// 			logger.Log("failed to create metric", "err", metricErr, "query_field_name",
			// 				currentCell.QField, "raw_value", currentCell.RawValue)

			// 			continue
			// 		}

			// 		collector.nvidiaExporter.sendMetric(ch, metric)
			// 	}
			// }

		} else {
			logger.Log("GPU类型不支持:", collector.gpuType)
			return nil
		}
	}
	return nil
}

// func HexToDecimal(hex string) (float64, error) {
// 	s := hex
// 	s = strings.ReplaceAll(s, "0x", "")
// 	s = strings.ReplaceAll(s, "0X", "")
// 	parsed, err := strconv.ParseUint(s, hexToDecimalBase, hexToDecimalUIntBitSize)

// 	return float64(parsed), err
// }

// func TransformRawValue(rawValue string, valueMultiplier float64) (float64, error) {
// 	trimmed := strings.TrimSpace(rawValue)
// 	if strings.HasPrefix(trimmed, "0x") {
// 		decimal, err := HexToDecimal(trimmed)
// 		if err != nil {
// 			return 0, fmt.Errorf("failed to transform raw value %q: %w", trimmed, err)
// 		}

// 		return decimal, nil
// 	}

// 	val := strings.ToLower(trimmed)

// 	switch val {
// 	case "enabled", "yes", "active":
// 		return 1, nil
// 	case "disabled", "no", "not active":
// 		return 0, nil
// 	case "default":
// 		return 0, nil
// 	case "exclusive_thread":
// 		return 1, nil
// 	case "prohibited":
// 		return 2, nil
// 	case "exclusive_process":
// 		return 3, nil
// 	default:
// 		return parseSanitizedValueWithBestEffort(val, valueMultiplier)
// 	}
// }

// func parseSanitizedValueWithBestEffort(
// 	sanitizedValue string,
// 	valueMultiplier float64,
// ) (float64, error) {
// 	allNums := numericRegex.FindAllString(sanitizedValue, 2) //nolint:mnd
// 	if len(allNums) != 1 {
// 		return -1, fmt.Errorf("could not parse number from value: %q", sanitizedValue)
// 	}

// 	parsed, err := strconv.ParseFloat(allNums[0], floatBitSize)
// 	if err != nil {
// 		return -1, fmt.Errorf("failed to parse float %q: %w", allNums[0], err)
// 	}

// 	return parsed * valueMultiplier, nil
// }

// type Row struct {
// 	QFieldToCells map[QField]Cell
// 	Cells         []Cell
// }

// type Cell struct {
// 	QField   QField
// 	RField   RField
// 	RawValue string
// }

// // RField stands for returned field - the field name as returned by the nvidia-smi.
// type RField string

// type Table struct {
// 	Rows          []Row
// 	RFields       []RField
// 	QFieldToCells map[QField][]Cell
// }

// func QFieldSliceToStringSlice(qs []QField) []string {
// 	r := make([]string, len(qs))
// 	for i, q := range qs {
// 		r[i] = string(q)
// 	}

// 	return r
// }

// func scrape(qFields []QField, nvidiaSmiCommand string, command runCmd) (int, *Table, error) {
// 	qFieldsJoined := strings.Join(QFieldSliceToStringSlice(qFields), ",")

// 	cmdAndArgs := strings.Fields(nvidiaSmiCommand)
// 	cmdAndArgs = append(cmdAndArgs, "--query-gpu="+qFieldsJoined)
// 	cmdAndArgs = append(cmdAndArgs, "--format=csv")

// 	var stdout bytes.Buffer

// 	var stderr bytes.Buffer

// 	cmd := exec.Command(cmdAndArgs[0], cmdAndArgs[1:]...) //nolint:gosec
// 	cmd.Stdout = &stdout
// 	cmd.Stderr = &stderr

// 	err := command(cmd)
// 	if err != nil {
// 		exitCode := -1

// 		var exitError *exec.ExitError
// 		if errors.As(err, &exitError) {
// 			exitCode = exitError.ExitCode()
// 		}

// 		return exitCode, nil, fmt.Errorf(
// 			"command failed: code: %d | command: %s | stdout: %s | stderr: %s: %w",
// 			exitCode,
// 			strings.Join(cmdAndArgs, " "),
// 			stdout.String(),
// 			stderr.String(),
// 			err,
// 		)
// 	}

// 	t, err := ParseCSVIntoTable(strings.TrimSpace(stdout.String()), qFields)
// 	if err != nil {
// 		return -1, nil, err
// 	}

// 	return 0, &t, nil
// }

// func toRFieldSlice(ss []string) []RField {
// 	r := make([]RField, len(ss))
// 	for i, s := range ss {
// 		r[i] = RField(s)
// 	}

// 	return r
// }

// func ParseCSVIntoTable(queryResult string, qFields []QField) (Table, error) {
// 	lines := strings.Split(strings.TrimSpace(queryResult), "\n")
// 	titlesLine := lines[0]
// 	valuesLines := lines[1:]
// 	rFields := toRFieldSlice(parseCSVLine(titlesLine))

// 	numCols := len(qFields)
// 	numRows := len(valuesLines)

// 	rows := make([]Row, numRows)

// 	qFieldToCells := make(map[QField][]Cell)
// 	for _, q := range qFields {
// 		qFieldToCells[q] = make([]Cell, numRows)
// 	}

// 	for rowIndex, valuesLine := range valuesLines {
// 		qFieldToCell := make(map[QField]Cell, numCols)
// 		cells := make([]Cell, numCols)
// 		rawValues := parseCSVLine(valuesLine)

// 		if len(qFields) != len(rFields) {
// 			return Table{}, fmt.Errorf(
// 				"field count mismatch: query fields: %d, returned fields: %d",
// 				len(qFields),
// 				len(rFields),
// 			)
// 		}

// 		for colIndex, rawValue := range rawValues {
// 			currentQField := qFields[colIndex]
// 			currentRField := rFields[colIndex]
// 			tableCell := Cell{
// 				QField:   currentQField,
// 				RField:   currentRField,
// 				RawValue: rawValue,
// 			}
// 			qFieldToCell[currentQField] = tableCell
// 			cells[colIndex] = tableCell
// 			qFieldToCells[currentQField][rowIndex] = tableCell
// 		}

// 		tableRow := Row{
// 			QFieldToCells: qFieldToCell,
// 			Cells:         cells,
// 		}

// 		rows[rowIndex] = tableRow
// 	}

// 	return Table{
// 		Rows:          rows,
// 		RFields:       rFields,
// 		QFieldToCells: qFieldToCells,
// 	}, nil
// }

// func parseCSVLine(line string) []string {
// 	values := strings.Split(line, ",")
// 	result := make([]string, len(values))

// 	for i, field := range values {
// 		result[i] = strings.TrimSpace(field)
// 	}

// 	return result
// }

// func (e *NvidiaExporter) sendMetric(ch chan<- prometheus.Metric, metric prometheus.Metric) {
// 	select {
// 	case <-e.ctx.Done():
// 		logger.Log("context done, return")
// 		return
// 	case ch <- metric:
// 	}
// }

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
