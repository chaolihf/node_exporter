package collector

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"time"

	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
)

type FileCheckCollector struct {
	enable   bool
	hostIp   string
	objectId string
}

type FileCheckInfo struct {
	collectTime int64
	modTime     int64
	ip          string
	objectId    string
	fileInfo    string
	filePath    string
}

// 声明全局变量用于内存中存储比较历史文件信息，键值对为指定文件路径:文件内容MD5
var lastFileInfoMap map[string][]byte

func init() {
	registerCollector("fileCheck", true, newFileCheckCollector)
}

func newFileCheckCollector(g_logger log.Logger) (Collector, error) {
	//初始化map
	lastFileInfoMap = make(map[string][]byte)
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
			jsonFileCheckInfo := jsonConfigInfos.GetJsonObject("fileCheck")
			return &FileCheckCollector{
				enable:   jsonFileCheckInfo.GetBool("enable"),
				hostIp:   jsonFileCheckInfo.GetString("hostIp"),
				objectId: jsonFileCheckInfo.GetString("objectId"),
			}, nil
		}
	}
	return &FileCheckCollector{
		enable: false,
	}, nil
}

func (collector *FileCheckCollector) Update(ch chan<- prometheus.Metric) error {
	//判断是否对文件变更进行采集
	if collector.enable {
		filePath := "config.json"
		content, err := os.ReadFile(filePath)
		if err != nil {
			logger.Log("读取文件出错:"+filePath, err)
			return err
		} else {
			jsonConfigInfos, err := jjson.NewJsonObject([]byte(content))
			if err != nil {
				logger.Log("JSON文件格式出错:", err)
				return err
			} else {
				//初始化字符串切片存放需要采集的指定路径下的文件
				for _, fileCheckPath := range jsonConfigInfos.GetJsonObject("fileCheck").GetJsonArray("filePath") {
					fileCheckPath := fileCheckPath.GetString("path")
					//判断指定路径下的文件是否存在，若文件存在
					exists, info := fileExists(fileCheckPath)
					if exists {
						content, err := os.ReadFile(fileCheckPath)
						if err != nil {
							logger.Log("读取文件出错:"+filePath, err)
							return nil
						} else {
							//判断该路径文件是否存在于map中
							if _, ok := lastFileInfoMap[fileCheckPath]; ok {
								//若文件内容未发生改变
								if bytes.Equal(lastFileInfoMap[fileCheckPath], content) {
									logger.Log("fileCheck", fmt.Sprintf("filePath:%s", fileCheckPath))
								} else {
									lastFileInfoMap[fileCheckPath] = content
									//获取文件指标metric
									ch <- createFileCheckMetric(content, DT_Changed, info, collector, fileCheckPath)
								}
							} else {
								lastFileInfoMap[fileCheckPath] = content
								ch <- createFileCheckMetric(content, DT_Add, info, collector, fileCheckPath)
							}
						}
					} else {
						ch <- createFileCheckMetric(nil, DT_Delete, info, collector, fileCheckPath)
					}
				}
				ch <- createSuccessMetric("fileCheck", 1)
			}
		}
	}
	return nil
}

// 判断文件是否存在
func fileExists(filePath string) (bool, fs.FileInfo) {
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false, nil
	} else {
		return true, info
	}
}

/*
创建fileCheck指标
collectTime int64
modTime     int64
ip          string
objectId    string
fileInfo    string
*/
func createFileCheckMetric(content []byte, metricType int, info fs.FileInfo, collector *FileCheckCollector, filePath string) prometheus.Metric {
	var tags = make(map[string]string)
	tags["collectTime"] = time.Now().Format("2006-01-02 15:04:05")
	if info == nil {
		tags["modTime"] = time.Now().Format("2006-01-02 15:04:05")
	} else {
		tags["modTime"] = info.ModTime().Format("2006-01-02 15:04:05")
	}
	tags["ip"] = collector.hostIp
	tags["objectId"] = collector.objectId
	tags["fileInfo"] = string(content)
	tags["filePath"] = filePath
	metricDesc := prometheus.NewDesc("fileCheck", "fileCheck", nil, tags)
	metric := prometheus.MustNewConstMetric(metricDesc, prometheus.CounterValue, float64(metricType))
	return metric
}
