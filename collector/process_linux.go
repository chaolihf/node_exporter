package collector

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/chaolihf/gopsutil/process"
	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

/*
保存的进程信息,processType为0表示全量进程，为1表示指定进程
*/
type ProcessInfo struct {
	command      string
	cpu          float64
	createTime   int64
	exec         string
	name         string
	numOpenFiles int32
	numThread    int32
	parentId     int32
	pid          int32
	rss          int64
	username     string
	vms          int64
	readBytes    int64
	readCount    int64
	readSpeed    float64
	writeBytes   int64
	writeCount   int64
	writeSpeed   float64
	status       string
}

type DesignedProcessInfo struct {
	command         string
	cpu             float64
	createTime      int64
	exec            string
	name            string
	numOpenFiles    int32
	numThread       int32
	parentId        int32
	pid             int32
	rss             int64
	username        string
	vms             int64
	readBytes       int64
	readCount       int64
	readSpeed       float64
	writeBytes      int64
	writeCount      int64
	writeSpeed      float64
	status          string
	processObjectId string
}

/*
定义Process收集类,enable为0表示不做采集，1表示全量采集，2表示指定进程采集，3表示全量+指定进程；designedType表示采集方式，false表示指定进程不做新老进程比较，true表示只返回变化较大的指定进程
*/
type ProcessCollector struct {
	interval                int
	cpuInterval             int64
	lastCollectTime         int64
	lastFullCollectTime     int64
	lastProcessInfo         []ProcessInfo
	lastDesignedProcessInfo []DesignedProcessInfo
	cpuOffset               int
	memoryOffset            int
	ioSpeedPerSecond        int
	openFileOffset          int
	threadOffset            int
	localLog                bool
	designed                []string
	enable                  int
	designedType            bool
	commandMap              map[string]string
}

var processMap map[int32]*process.Process

func init() {
	registerCollector("process", true, newProcessCollector)
	processMap = make(map[int32]*process.Process)
}

/*
初始化收集器
*/
func newProcessCollector(g_logger log.Logger) (Collector, error) {
	logger = g_logger
	filePath := "config.json"
	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Log("读取文件出错:"+filePath, err)
	} else {
		jsonConfigInfos, err := jjson.NewJsonObject([]byte(content))
		if err != nil {
			logger.Log("JSON文件格式出错:", err)
			return nil, err
		} else {
			jsonProcessInfo := jsonConfigInfos.GetJsonObject("process")
			//获取指定进程名称
			commands := []string{}
			processObjectIds := []string{}
			for _, designedProcess := range jsonConfigInfos.GetJsonArray("designedProcess") {
				designedCommands := designedProcess.GetJsonArray("command")
				for _, designedCommand := range designedCommands {
					commands = append(commands, designedCommand.GetStringValue())
				}
				designedProcessObjectIds := designedProcess.GetJsonArray("process_object_id")
				for _, designedProcessObjectId := range designedProcessObjectIds {
					processObjectIds = append(processObjectIds, designedProcessObjectId.GetStringValue())
				}
			}
			commandMap := make(map[string]string)
			for i := 0; i < len(commands); i++ {
				command := commands[i]
				processObjectId := processObjectIds[i]
				commandMap[command] = processObjectId
			}
			return &ProcessCollector{
				interval:            jsonProcessInfo.GetInt("interval"),
				cpuInterval:         jsonConfigInfos.GetLong("cpuInterval"),
				lastCollectTime:     0,
				lastFullCollectTime: 0,
				cpuOffset:           jsonProcessInfo.GetInt("cpuOffset"),
				memoryOffset:        jsonProcessInfo.GetInt("memoryOffset"),
				ioSpeedPerSecond:    jsonProcessInfo.GetInt("ioSpeedPerSecond"),
				openFileOffset:      jsonProcessInfo.GetInt("openFileOffset"),
				threadOffset:        jsonProcessInfo.GetInt("threadOffset"),
				localLog:            jsonProcessInfo.GetBool("localLog"),
				enable:              jsonProcessInfo.GetInt("enable"),
				designedType:        jsonProcessInfo.GetBool("designedType"),
				designed:            commands,
				commandMap:          commandMap,
			}, nil
		}
	}
	return &ProcessCollector{
		interval:            86400,
		cpuInterval:         5,
		lastCollectTime:     0,
		lastFullCollectTime: 0,
		cpuOffset:           30,
		memoryOffset:        200000000,
		ioSpeedPerSecond:    5000000,
		openFileOffset:      100,
		threadOffset:        30,
		localLog:            true,
		enable:              1,
		designedType:        false,
		designed:            nil,
		commandMap:          nil,
	}, nil
}

/*
每隔一段时间更新全量的数据，否正根据规则只更新变更的数据
*/
func (collector *ProcessCollector) Update(ch chan<- prometheus.Metric) error {
	//lastTime := collector.lastCollectTime
	lastFullTime := collector.lastFullCollectTime
	designedType := collector.designedType
	currentTime := time.Now().Unix()
	var err error
	var allProcessInfo []ProcessInfo
	var designedProcess []DesignedProcessInfo
	var isSendAll bool
	if lastFullTime == 0 || currentTime-lastFullTime > int64(collector.interval) {
		isSendAll = true
		//collector.lastFullCollectTime = currentTime
	} else {
		isSendAll = false
	}
	allProcessInfo, designedProcess, err = getAllProcess(ch, collector, isSendAll)
	//指定进程按pid从小到大排序
	sort.Slice(designedProcess, func(i, j int) bool {
		return designedProcess[i].pid < designedProcess[j].pid
	})
	if err != nil {
		ch <- createSuccessMetric("process", 0)
		return err
	} else {
		//判断是否指定进程
		if designedProcess != nil {
			if designedType {
				if collector.localLog {
					for _, process := range designedProcess {
						logger.Log("designedProcess", fmt.Sprintf("pid:%d,cpu:%f,vms:%d,rss:%d,files:%d,thread:%d,read:%d,write:%d",
							process.pid, process.cpu, process.vms, process.rss, process.numOpenFiles,
							process.numThread, process.readBytes, process.writeBytes))
					}
				}

				sort.Slice(designedProcess, func(i, j int) bool {
					return designedProcess[i].pid < designedProcess[j].pid
				})
				if !isSendAll {
					addProcessInfos, changedProccessInfos, removedProcessInfos, newAllProcessInfos := getChangedDesignedProcess(collector, designedProcess)
					for _, process := range addProcessInfos {
						ch <- createDesignedProcessMetric(&process, DT_Add)
					}
					for _, process := range changedProccessInfos {
						ch <- createDesignedProcessMetric(&process, DT_Changed)
					}
					for _, process := range removedProcessInfos {
						ch <- createDesignedProcessMetric(&process, DT_Delete)
					}
					collector.lastDesignedProcessInfo = newAllProcessInfos
				} else {
					for _, process := range designedProcess {
						ch <- createDesignedProcessMetric(&process, DT_All)
					}
					collector.lastFullCollectTime = currentTime
					collector.lastDesignedProcessInfo = designedProcess
				}
				ch <- createSuccessMetric("designedProcess", 1)
				collector.lastCollectTime = currentTime
			} else {
				if collector.localLog {
					for _, process := range designedProcess {
						logger.Log("designedProcess", fmt.Sprintf("pid:%d,cpu:%f,vms:%d,rss:%d,files:%d,thread:%d,read:%d,write:%d",
							process.pid, process.cpu, process.vms, process.rss, process.numOpenFiles,
							process.numThread, process.readBytes, process.writeBytes))
					}
				}

				sort.Slice(designedProcess, func(i, j int) bool {
					return designedProcess[i].pid < designedProcess[j].pid
				})

				for _, process := range designedProcess {
					ch <- createDesignedProcessMetric(&process, DT_All)
				}
				collector.lastDesignedProcessInfo = designedProcess
			}
			ch <- createSuccessMetric("designedProcess", 1)
		}
		if allProcessInfo != nil {
			//是否打印本地日志
			if collector.localLog {
				for _, process := range allProcessInfo {
					logger.Log("Process", fmt.Sprintf("pid:%d,cpu:%f,vms:%d,rss:%d,files:%d,thread:%d,read:%d,write:%d",
						process.pid, process.cpu, process.vms, process.rss, process.numOpenFiles,
						process.numThread, process.readBytes, process.writeBytes))
				}
			}

			sort.Slice(allProcessInfo, func(i, j int) bool {
				return allProcessInfo[i].pid < allProcessInfo[j].pid
			})
			if !isSendAll {
				addProcessInfos, changedProccessInfos, removedProcessInfos, newAllProcessInfos := getChangedProcess(collector, allProcessInfo)
				for _, process := range addProcessInfos {
					ch <- createProcessMetric(&process, DT_Add)
				}
				for _, process := range changedProccessInfos {
					ch <- createProcessMetric(&process, DT_Changed)
				}
				for _, process := range removedProcessInfos {
					ch <- createProcessMetric(&process, DT_Delete)
				}
				collector.lastProcessInfo = newAllProcessInfos
			} else {
				for _, process := range allProcessInfo {
					ch <- createProcessMetric(&process, DT_All)
				}
				collector.lastProcessInfo = allProcessInfo
				collector.lastFullCollectTime = currentTime
			}
			ch <- createSuccessMetric("process", 1)
			collector.lastCollectTime = currentTime
		}
		return nil
	}
}

/*
比较新老进程信息获取增量变化信息
完整的进程包括新增的进程和未变更的进程（进程信息使用老的）以及变更的进程
返回：增加的进程，变更的进程，删除的进程，完整的进程信息
*/
func getChangedDesignedProcess(collector *ProcessCollector, newProcesses []DesignedProcessInfo) ([]DesignedProcessInfo, []DesignedProcessInfo, []DesignedProcessInfo, []DesignedProcessInfo) {
	var (
		newProcessesArr     []DesignedProcessInfo
		changedProcesses    []DesignedProcessInfo
		deletedProcessesArr []DesignedProcessInfo
		allProcessesArr     []DesignedProcessInfo
	)
	oldProcesses := collector.lastDesignedProcessInfo
	oldIndex := 0
	newIndex := 0
	interval := time.Now().Unix() - collector.lastCollectTime
	for oldIndex < len(oldProcesses) && newIndex < len(newProcesses) {
		oldPID := oldProcesses[oldIndex].pid
		newPID := newProcesses[newIndex].pid
		if oldPID == newPID {
			if areDesignedProcessesChanged(&oldProcesses[oldIndex], &newProcesses[newIndex], collector, interval) {
				changedProcesses = append(changedProcesses, newProcesses[newIndex])
				allProcessesArr = append(allProcessesArr, newProcesses[newIndex])
			} else {
				allProcessesArr = append(allProcessesArr, oldProcesses[oldIndex])
			}
			oldIndex++
			newIndex++
		} else if oldPID < newPID {
			deletedProcessesArr = append(deletedProcessesArr, oldProcesses[oldIndex])
			oldIndex++
		} else {
			newProcessesArr = append(newProcessesArr, newProcesses[newIndex])
			allProcessesArr = append(allProcessesArr, newProcesses[newIndex])
			newIndex++
		}
	}
	for oldIndex < len(oldProcesses) {
		deletedProcessesArr = append(deletedProcessesArr, oldProcesses[oldIndex])
		oldIndex++
	}
	for newIndex < len(newProcesses) {
		newProcessesArr = append(newProcessesArr, newProcesses[newIndex])
		allProcessesArr = append(allProcessesArr, newProcesses[newIndex])
		newIndex++
	}
	return newProcessesArr, changedProcesses, deletedProcessesArr, allProcessesArr
}

/*
比较新老进程信息获取增量变化信息
完整的进程包括新增的进程和未变更的进程（进程信息使用老的）以及变更的进程
返回：增加的进程，变更的进程，删除的进程，完整的进程信息
*/
func getChangedProcess(collector *ProcessCollector, newProcesses []ProcessInfo) ([]ProcessInfo, []ProcessInfo, []ProcessInfo, []ProcessInfo) {
	var (
		newProcessesArr     []ProcessInfo
		changedProcesses    []ProcessInfo
		deletedProcessesArr []ProcessInfo
		allProcessesArr     []ProcessInfo
	)
	oldProcesses := collector.lastProcessInfo
	oldIndex := 0
	newIndex := 0
	interval := time.Now().Unix() - collector.lastCollectTime
	for oldIndex < len(oldProcesses) && newIndex < len(newProcesses) {
		oldPID := oldProcesses[oldIndex].pid
		newPID := newProcesses[newIndex].pid
		if oldPID == newPID {
			if areProcessesChanged(&oldProcesses[oldIndex], &newProcesses[newIndex], collector, interval) {
				changedProcesses = append(changedProcesses, newProcesses[newIndex])
				allProcessesArr = append(allProcessesArr, newProcesses[newIndex])
			} else {
				allProcessesArr = append(allProcessesArr, oldProcesses[oldIndex])
			}
			oldIndex++
			newIndex++
		} else if oldPID < newPID {
			deletedProcessesArr = append(deletedProcessesArr, oldProcesses[oldIndex])
			oldIndex++
		} else {
			newProcessesArr = append(newProcessesArr, newProcesses[newIndex])
			allProcessesArr = append(allProcessesArr, newProcesses[newIndex])
			newIndex++
		}
	}
	for oldIndex < len(oldProcesses) {
		deletedProcessesArr = append(deletedProcessesArr, oldProcesses[oldIndex])
		oldIndex++
	}
	for newIndex < len(newProcesses) {
		newProcessesArr = append(newProcessesArr, newProcesses[newIndex])
		allProcessesArr = append(allProcessesArr, newProcesses[newIndex])
		newIndex++
	}
	return newProcessesArr, changedProcesses, deletedProcessesArr, allProcessesArr
}

/*
比较进程参数是否发生较大的改变
*/
func areProcessesChanged(oldProcessInfo, newProcessInfo *ProcessInfo, collector *ProcessCollector, interval int64) bool {
	if math.Abs(oldProcessInfo.cpu-newProcessInfo.cpu) > float64(collector.cpuOffset) {
		return true
	}
	if math.Abs(float64(oldProcessInfo.vms)-float64(newProcessInfo.vms)) > float64(collector.memoryOffset) {
		return true
	}
	if math.Abs(float64(oldProcessInfo.rss)-float64(newProcessInfo.rss)) > float64(collector.memoryOffset) {
		return true
	}
	if math.Abs(float64(oldProcessInfo.numOpenFiles)-float64(newProcessInfo.numOpenFiles)) > float64(collector.openFileOffset) {
		return true
	}
	if math.Abs(float64(oldProcessInfo.numThread)-float64(newProcessInfo.numThread)) > float64(collector.threadOffset) {
		return true
	}
	if collector.lastCollectTime != 0 {
		changed := false
		var readSpeed, writeSpeed float64
		if oldProcessInfo.readBytes != 0 && oldProcessInfo.readSpeed > 0 {
			readSpeed := math.Abs(float64(oldProcessInfo.readBytes)-float64(newProcessInfo.readBytes)) / float64(interval)
			if math.Abs(readSpeed-oldProcessInfo.readSpeed) > float64(collector.ioSpeedPerSecond) {
				changed = true
			}
		}
		if oldProcessInfo.writeBytes != 0 && oldProcessInfo.writeSpeed > 0 {
			writeSpeed := math.Abs(float64(oldProcessInfo.writeBytes)-float64(newProcessInfo.writeBytes)) / float64(interval)
			if math.Abs(writeSpeed-oldProcessInfo.writeSpeed) > float64(collector.ioSpeedPerSecond) {
				changed = true
			}
		}
		if changed {
			newProcessInfo.readSpeed = readSpeed
			newProcessInfo.writeSpeed = writeSpeed
			return true
		} else {
			oldProcessInfo.readSpeed = readSpeed
			oldProcessInfo.writeSpeed = writeSpeed
			return false
		}
	}
	if !strings.EqualFold(oldProcessInfo.status, newProcessInfo.status) {
		return true
	}
	return false
}

/*
比较进程参数是否发生较大的改变
*/
func areDesignedProcessesChanged(oldProcessInfo, newProcessInfo *DesignedProcessInfo, collector *ProcessCollector, interval int64) bool {
	if math.Abs(oldProcessInfo.cpu-newProcessInfo.cpu) > float64(collector.cpuOffset) {
		return true
	}
	if math.Abs(float64(oldProcessInfo.vms)-float64(newProcessInfo.vms)) > float64(collector.memoryOffset) {
		return true
	}
	if math.Abs(float64(oldProcessInfo.rss)-float64(newProcessInfo.rss)) > float64(collector.memoryOffset) {
		return true
	}
	if math.Abs(float64(oldProcessInfo.numOpenFiles)-float64(newProcessInfo.numOpenFiles)) > float64(collector.openFileOffset) {
		return true
	}
	if math.Abs(float64(oldProcessInfo.numThread)-float64(newProcessInfo.numThread)) > float64(collector.threadOffset) {
		return true
	}
	if collector.lastCollectTime != 0 {
		changed := false
		var readSpeed, writeSpeed float64
		if oldProcessInfo.readBytes != 0 && oldProcessInfo.readSpeed > 0 {
			readSpeed := math.Abs(float64(oldProcessInfo.readBytes)-float64(newProcessInfo.readBytes)) / float64(interval)
			if math.Abs(readSpeed-oldProcessInfo.readSpeed) > float64(collector.ioSpeedPerSecond) {
				changed = true
			}
		}
		if oldProcessInfo.writeBytes != 0 && oldProcessInfo.writeSpeed > 0 {
			writeSpeed := math.Abs(float64(oldProcessInfo.writeBytes)-float64(newProcessInfo.writeBytes)) / float64(interval)
			if math.Abs(writeSpeed-oldProcessInfo.writeSpeed) > float64(collector.ioSpeedPerSecond) {
				changed = true
			}
		}
		if changed {
			newProcessInfo.readSpeed = readSpeed
			newProcessInfo.writeSpeed = writeSpeed
			return true
		} else {
			oldProcessInfo.readSpeed = readSpeed
			oldProcessInfo.writeSpeed = writeSpeed
			return false
		}
	}
	if !strings.EqualFold(oldProcessInfo.status, newProcessInfo.status) {
		return true
	}
	return false
}

/*
根据系统进程获取进程数据
*/
func getProccessInfo(item *process.Process) (ProcessInfo, *process.Process) {
	pi := ProcessInfo{}
	username, _ := item.Username()
	name, _ := item.Name()
	command, _ := item.Cmdline()
	memory, _ := item.MemoryInfo()
	numThread, _ := item.NumThreads()
	numOpenFiles, _ := item.NumFDs()
	createTime, _ := item.CreateTime()
	parentId, _ := item.Ppid()
	cpu, _ := item.Percent(time.Duration(0))
	exec, _ := item.Exe()
	ioCounters, _ := item.IOCounters()
	status, _ := item.Status()
	pi.username = username
	pi.name = name
	pi.command = extractString(command, 120, 120, "|||")
	if memory != nil {
		pi.rss = int64(memory.RSS)
		pi.vms = int64(memory.VMS)
	} else {
		pi.rss = -1
		pi.vms = -1
	}
	pi.numThread = numThread
	pi.numOpenFiles = numOpenFiles
	pi.createTime = createTime
	pi.parentId = parentId
	pi.pid = item.Pid
	pi.cpu = cpu
	pi.exec = extractString(exec, 120, 120, "|||")
	if ioCounters != nil {
		pi.readBytes = int64(ioCounters.ReadBytes)
		pi.writeBytes = int64(ioCounters.WriteBytes)
		pi.readCount = int64(ioCounters.ReadCount)
		pi.writeCount = int64(ioCounters.WriteCount)
	} else {
		pi.readBytes = -1
		pi.writeBytes = -1
		pi.readCount = -1
		pi.writeCount = -1
	}
	pi.status = status[0]
	return pi, item
}

/*
根据系统进程获取指定进程数据
*/
func getDesignedProccessInfo(item *process.Process, collector *ProcessCollector, cmd string) (DesignedProcessInfo, *process.Process) {
	commandMap := collector.commandMap
	pi := DesignedProcessInfo{}
	username, _ := item.Username()
	name, _ := item.Name()
	command, _ := item.Cmdline()
	memory, _ := item.MemoryInfo()
	numThread, _ := item.NumThreads()
	numOpenFiles, _ := item.NumFDs()
	createTime, _ := item.CreateTime()
	parentId, _ := item.Ppid()
	cpu, _ := item.Percent(time.Duration(0))
	exec, _ := item.Exe()
	ioCounters, _ := item.IOCounters()
	status, _ := item.Status()
	pi.username = username
	pi.name = name
	pi.command = extractString(command, 120, 120, "|||")
	if memory != nil {
		pi.rss = int64(memory.RSS)
		pi.vms = int64(memory.VMS)
	} else {
		pi.rss = -1
		pi.vms = -1
	}
	pi.numThread = numThread
	pi.numOpenFiles = numOpenFiles
	pi.createTime = createTime
	pi.parentId = parentId
	pi.pid = item.Pid
	pi.cpu = cpu
	pi.exec = extractString(exec, 120, 120, "|||")
	if ioCounters != nil {
		pi.readBytes = int64(ioCounters.ReadBytes)
		pi.writeBytes = int64(ioCounters.WriteBytes)
		pi.readCount = int64(ioCounters.ReadCount)
		pi.writeCount = int64(ioCounters.WriteCount)
	} else {
		pi.readBytes = -1
		pi.writeBytes = -1
		pi.readCount = -1
		pi.writeCount = -1
	}
	pi.status = status[0]
	processObjectId := commandMap[cmd]
	pi.processObjectId = processObjectId
	return pi, item
}

/*
聚合指标
*/
func appendDesigned(item ProcessInfo, collector *ProcessCollector, cmd string) DesignedProcessInfo {
	pi := DesignedProcessInfo{}
	commandMap := collector.commandMap
	pi.username = item.username
	pi.name = item.name
	pi.command = item.command
	pi.rss = item.rss
	pi.vms = item.vms
	pi.numThread = item.numThread
	pi.numOpenFiles = item.numOpenFiles
	pi.createTime = item.createTime
	pi.parentId = item.parentId
	pi.pid = item.pid
	pi.cpu = item.cpu
	pi.exec = item.exec
	pi.readBytes = item.readBytes
	pi.writeBytes = item.writeBytes
	pi.readCount = item.readCount
	pi.writeCount = item.writeCount
	pi.status = item.status
	processObjectId := commandMap[cmd]
	pi.processObjectId = processObjectId
	return pi
}

// 替换无效字符为?
func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	} else {
		return strings.ToValidUTF8(s, "?")
	}
}

/*
创建进程指标
metricType : 0表示全量 1表示增量加 2表示增量更新 3表示增量删除
*/
func createProcessMetric(item *ProcessInfo, metricType int) prometheus.Metric {
	var tags = make(map[string]string)
	tags["username"] = sanitizeUTF8(item.username)
	tags["name"] = sanitizeUTF8(item.name)
	tags["command"] = sanitizeUTF8(item.command)
	tags["rss"] = fmt.Sprintf("%d", item.rss)
	tags["vms"] = fmt.Sprintf("%d", item.vms)
	tags["numThread"] = fmt.Sprintf("%d", item.numThread)
	tags["numOpenFiles"] = fmt.Sprintf("%d", item.numOpenFiles)
	tags["createTime"] = fmt.Sprintf("%d", item.createTime)
	tags["parentId"] = fmt.Sprintf("%d", item.parentId)
	tags["pid"] = fmt.Sprintf("%d", item.pid)
	tags["cpu"] = fmt.Sprintf("%f", item.cpu)
	tags["exec"] = sanitizeUTF8(item.exec)
	tags["readBytes"] = fmt.Sprintf("%d", item.readBytes)
	tags["writeBytes"] = fmt.Sprintf("%d", item.writeBytes)
	tags["readCount"] = fmt.Sprintf("%d", item.readCount)
	tags["writeCount"] = fmt.Sprintf("%d", item.writeCount)
	tags["status"] = item.status
	metricDesc := prometheus.NewDesc("process", "process", nil, tags)
	metric := prometheus.MustNewConstMetric(metricDesc, prometheus.CounterValue, float64(metricType))
	return metric
}

/*
创建指定进程指标
metricType : 0表示全量 1表示增量加 2表示增量更新 3表示增量删除
*/
func createDesignedProcessMetric(item *DesignedProcessInfo, metricType int) prometheus.Metric {
	var tags = make(map[string]string)
	tags["username"] = sanitizeUTF8(item.username)
	tags["name"] = sanitizeUTF8(item.name)
	tags["command"] = sanitizeUTF8(item.command)
	tags["rss"] = fmt.Sprintf("%d", item.rss)
	tags["vms"] = fmt.Sprintf("%d", item.vms)
	tags["numThread"] = fmt.Sprintf("%d", item.numThread)
	tags["numOpenFiles"] = fmt.Sprintf("%d", item.numOpenFiles)
	tags["createTime"] = fmt.Sprintf("%d", item.createTime)
	tags["parentId"] = fmt.Sprintf("%d", item.parentId)
	tags["pid"] = fmt.Sprintf("%d", item.pid)
	tags["cpu"] = fmt.Sprintf("%f", item.cpu)
	tags["exec"] = sanitizeUTF8(item.exec)
	tags["readBytes"] = fmt.Sprintf("%d", item.readBytes)
	tags["writeBytes"] = fmt.Sprintf("%d", item.writeBytes)
	tags["readCount"] = fmt.Sprintf("%d", item.readCount)
	tags["writeCount"] = fmt.Sprintf("%d", item.writeCount)
	tags["status"] = item.status
	tags["process_object_id"] = item.processObjectId
	metricDesc := prometheus.NewDesc("designedProcess", "designedProcess", nil, tags)
	metric := prometheus.MustNewConstMetric(metricDesc, prometheus.CounterValue, float64(metricType))
	return metric
}

var mu sync.Mutex

/*
get all process and sort by pid
@return 获取进程信息
*/
func getAllProcess(ch chan<- prometheus.Metric, collector *ProcessCollector, isSendAll bool) ([]ProcessInfo, []DesignedProcessInfo, error) {
	collecType := collector.enable
	//判断操作类型,enable为0表示不做采集，1表示全量采集，2表示指定进程采集，3表示全量+指定进程
	if collecType == 0 {
		return nil, nil, nil
	} else {
		//根据pid从小到大排序获取所有进程信息
		allProcess, err := process.Processes()
		if err != nil {
			logger.Log(err.Error())
			return nil, nil, err
		} else {
			if collecType == 1 {
				newProcesses := []ProcessInfo{}
				for _, process1 := range allProcess {
					//获取当前新进程的PID
					processPid := process1.Pid
					mu.Lock()
					if oldProcess, ok := processMap[processPid]; ok {
						processInfo, lastProcess := getProccessInfo(oldProcess)
						newProcesses = append(newProcesses, processInfo)
						processMap[processPid] = lastProcess
					} else {
						processInfo, lastProcess := getProccessInfo(process1)
						newProcesses = append(newProcesses, processInfo)
						processMap[processPid] = lastProcess
					}
					mu.Unlock()
				}
				return newProcesses, nil, nil
			} else if collecType == 2 {
				designedProcessResult := []DesignedProcessInfo{}
				commands := collector.designed
				//判断是否指定进程
				if commands != nil {
					for _, designedCommand := range commands {
						// 遍历每个进程名称，根据pid顺序进行遍历
						for _, p := range allProcess {
							command, err := p.Cmdline()
							if err != nil {
								logger.Log("process command retrieval error")
							}
							// 检查进程名称是否匹配
							if strings.Contains(command, designedCommand) {
								processPid := p.Pid
								if processMap != nil {
									mu.Lock()
									if _, ok := processMap[processPid]; ok {
										p = processMap[processPid]
										processInfo, lastProcess := getDesignedProccessInfo(p, collector, designedCommand)
										designedProcessResult = append(designedProcessResult, processInfo)
										processMap[processPid] = lastProcess
									} else {
										processInfo, lastProcess := getDesignedProccessInfo(p, collector, designedCommand)
										designedProcessResult = append(designedProcessResult, processInfo)
										processMap[processPid] = lastProcess
									}
									mu.Unlock()
								} else {
									mu.Lock()
									processMap = make(map[int32]*process.Process)
									processInfo, lastProcess := getDesignedProccessInfo(p, collector, designedCommand)
									designedProcessResult = append(designedProcessResult, processInfo)
									processMap[processPid] = lastProcess
									mu.Unlock()
								}
							}
						}
					}
					return nil, designedProcessResult, nil
				} else {
					return nil, nil, nil
				}
			} else {
				newProcesses := []ProcessInfo{}
				for _, process1 := range allProcess {
					processPid := process1.Pid
					//若该pid存在于先前的map中
					if _, ok := processMap[processPid]; ok {
						mu.Lock()
						//根据pid获取进程
						process1 = processMap[processPid]
						processInfo, lastProcess := getProccessInfo(process1)
						newProcesses = append(newProcesses, processInfo)
						processMap[processPid] = lastProcess
						mu.Unlock()
					} else {
						processInfo, lastProcess := getProccessInfo(process1)
						newProcesses = append(newProcesses, processInfo)
						mu.Lock()
						processMap[processPid] = lastProcess
						mu.Unlock()
					}
				}
				designedProcessResult := []DesignedProcessInfo{}
				designedCommands := collector.designed
				//判断是否指定进程
				if designedCommands != nil {
					for _, designedCommand := range designedCommands {
						// 遍历每个进程名称
						for _, p := range newProcesses {
							command := p.command
							// 检查进程名称是否匹配
							if strings.Contains(command, designedCommand) {
								designedP := appendDesigned(p, collector, designedCommand)
								designedProcessResult = append(designedProcessResult, designedP)
							}
						}
					}
					return newProcesses, designedProcessResult, nil
				} else {
					return newProcesses, nil, nil
				}
			}
		}
	}
}

/*
从内容中抽取特定长度的关键信息
content: 源字符串
head: 头部抽取的长度
tail: 尾部抽取的长度
sperator: 头部和尾部的分割符
*/
func extractString(content string, head int, tail int, sperator string) string {
	size := len(content)
	if size < head+tail {
		return content
	} else {
		return fmt.Sprintf("%s%s%s", content[:head], sperator, content[size-tail:])
	}

}
