/*
*
@description  实现IScriptPlugin接口的http插件
*/
package icmp

import (
	"bytes"
	"context"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	stdlog "log"

	"github.com/chaolihf/node_exporter/pkg/utils"
	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/errgroup"
)

var logger log.Logger

type icmpCollector struct {
	TargetName string
	IcmpType   string
}

var (
	// icmpID            int
	icmpSequence      uint16
	icmpSequenceMutex sync.Mutex
	//DefaultICMPTTL    = 64
	//设置每次ping的包数，默认值为4
	packetNum int = 4
	//设置traceroute的最大TTL值，默认为20
	maxTracerouteTTL int = 20
	//traceroute单次的包大小，默认为32
	traceroutePacketSize int = 32
)

var isIcmpInited = false

func SetLogger(globalLogger log.Logger) {
	if !isIcmpInited {
		logger = globalLogger
		//sshclient.SetLogger(globalLogger)
		isIcmpInited = true
	}
}

func RequestHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	registry := prometheus.NewRegistry()
	targetName := params.Get("target")
	//声明icmp操作类型
	var icmpType string
	//判断是否有icmpType参数，没有则默认为0
	if params.Has("icmpType") {
		//0代表只采集ping,1代表只采集traceroute,2代表同时采集ping和traceroute
		icmpType = params.Get("icmpType")
	} else {
		icmpType = "0"
	}
	if targetName == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing target parameter!"))
		return
	}

	registry.MustRegister(&icmpCollector{TargetName: targetName, IcmpType: icmpType})
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func (collector *icmpCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (collector *icmpCollector) Collect(ch chan<- prometheus.Metric) {
	//若为0则表示只采集并返回ping数据，1表示只返回traceroute数据，2表示同时采集ping和traceroute数据
	if collector.IcmpType == "0" || collector.IcmpType == "" {
		metrics := getIcmpResult(collector.TargetName)
		for _, metric := range metrics {
			ch <- metric
		}
	} else if collector.IcmpType == "1" {
		metrics := getTracerouteResult(collector.TargetName)
		for _, metric := range metrics {
			ch <- metric
		}
	} else {
		metrics := getIcmpResult(collector.TargetName)
		traceRouteMetrics := getTracerouteResult(collector.TargetName)
		for _, metric := range metrics {
			ch <- metric
		}
		for _, tracerouteMetric := range traceRouteMetrics {
			ch <- tracerouteMetric
		}
	}

}

func getICMPSequence() uint16 {
	icmpSequenceMutex.Lock()
	defer icmpSequenceMutex.Unlock()
	icmpSequence++
	return icmpSequence
}

type ICMPScriptPlugin struct {
	logger             log.Logger
	DontFragment       bool
	sourceIPAddress    string
	PayloadSize        int
	TTL                int
	Deadline           int
	IPProtocol         string `yaml:"preferred_ip_protocol,omitempty"` // Defaults to "ip6".
	IPProtocolFallback bool   `yaml:"ip_protocol_fallback,omitempty"`
}

func NewICMPScriptPlugin(logger log.Logger) *ICMPScriptPlugin {
	return &ICMPScriptPlugin{
		logger:             logger,
		DontFragment:       false,
		TTL:                DefaultICMPTTL,
		Deadline:           5,
		IPProtocol:         "ip4",
		IPProtocolFallback: true,
	}
}

// 获取traceroute指标并拼装
func getTracerouteResult(targetName string) []prometheus.Metric {
	var metrics []prometheus.Metric

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 构建traceroute命令
	//cmd := exec.Command("traceroute", "-m", strconv.Itoa(maxTracerouteTTL), targetName, strconv.Itoa(traceroutePacketSize))
	cmd := exec.CommandContext(ctx, "traceroute", "-m", strconv.Itoa(maxTracerouteTTL), targetName, strconv.Itoa(traceroutePacketSize))

	// 创建一个bytes.Buffer来捕获命令的输出
	g, ctx := errgroup.WithContext(ctx)
	var out []byte
	var err error

	// 启动命令并捕获输出
	g.Go(func() error {
		out, err = cmd.CombinedOutput()
		if err != nil {
			level.Error(logger).Log("msg", "Error executing traceroute:", "err", err)
		}
		return err
	})

	// 等待命令完成或超时
	if err := g.Wait(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			level.Error(logger).Log("msg", "Error executing traceroute:", "err", err)
		}
	}

	// 如果没有超时且命令执行成功，打印结果
	if ctx.Err() != context.DeadlineExceeded {
		level.Info(logger).Log("msg", "Successsully executing traceroute:", "output", string(out))
	}

	tracerouteResult := string(out)

	metrics = append(metrics, createTracerouteMetric(tracerouteResult))

	return metrics
}

func createTracerouteMetric(tracerouteResult string) prometheus.Metric {
	var tags = make(map[string]string)
	tags["traceroute_result"] = tracerouteResult
	// 第一个参数为指标名称，第二个参数为指标的解释或描述
	metricDesc := prometheus.NewDesc("traceroute_metric", "tracerouteMetric", nil, tags)
	metric := prometheus.MustNewConstMetric(metricDesc, prometheus.CounterValue, float64(0))
	return metric
}

func getIcmpResult(targetName string) []prometheus.Metric {
	localPlugin := NewICMPScriptPlugin(logger)
	var metrics []prometheus.Metric
	probeSuccessGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})
	probeDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})
	probeLossGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_packet_loss",
		Help: "Returns the number of lost packets ",
	})
	probeMinDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_min_duration_seconds",
		Help: "Returns the minimum time for a single probe ",
	})
	probeMaxDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_max_duration_seconds",
		Help: "Returns the maximum time for a single probe ",
	})

	// 使用批量探测
	successCount, durations, lossCount, probeIPProtocolGauge, probeIPAddrHash := ProbeICMP(localPlugin, targetName, packetNum)

	// 统计指标
	if successCount > 0 {
		probeSuccessGauge.Set(1)
	} else {
		probeSuccessGauge.Set(0)
	}
	probeLossGauge.Set(float64(lossCount) / float64(packetNum))
	sort.Float64s(durations)
	probeMinDurationGauge.Set(durations[0])
	probeMaxDurationGauge.Set(durations[len(durations)-1])
	probeDurationGauge.Set(sum(durations) / float64(packetNum))

	metrics = append(metrics, probeSuccessGauge)
	metrics = append(metrics, probeDurationGauge)
	metrics = append(metrics, probeLossGauge)
	metrics = append(metrics, probeMinDurationGauge)
	metrics = append(metrics, probeMaxDurationGauge)
	metrics = append(metrics, probeIPProtocolGauge)
	metrics = append(metrics, probeIPAddrHash)
	return metrics
}

func sum(arr []float64) float64 {
	total := 0.0
	for _, v := range arr {
		total += v
	}
	return total
}

// 初始化配置文件
func init() {

	filePath := "icmpConfig.json"
	content, err := utils.ReadDataFromFile(filePath)
	if err != nil {
		stdlog.Printf("读取文件出错:%s,%s", filePath, err.Error())
	} else {
		jsonConfigInfos, err := jjson.NewJsonObject([]byte(content))
		if err != nil {
			level.Error(logger).Log("msg", "Error json format", "err", err)
		} else {
			maxTracerouteTTL = jsonConfigInfos.GetInt("maxTracerouteTTL")
			packetNum = jsonConfigInfos.GetInt("packetNum")
			traceroutePacketSize = jsonConfigInfos.GetInt("traceroutePacketSize")
		}

	}

	//初始化ICMP采集配置
	// plugin = NewICMPScriptPlugin(logger)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// PID is typically 1 when running in a container; in that case, set
	// the ICMP echo ID to a random value to avoid potential clashes with
	// other blackbox_exporter instances. See #411.
	// if pid := os.Getpid(); pid == 1 {
	// 	icmpID = r.Intn(1 << 16)
	// } else {
	// 	icmpID = pid & 0xffff
	// }

	// Start the ICMP echo sequence at a random offset to prevent them from
	// being in sync when several blackbox_exporter instances are restarted
	// at the same time. See #411.
	icmpSequence = uint16(r.Intn(1 << 16))
}

func ProbeICMP(thisPlugin *ICMPScriptPlugin, target string, probeCount int) (successCount int, durations []float64, lossCount int, probeIPProtocolGauge prometheus.Gauge, probeIPAddrHash prometheus.Gauge) {
	var (
		requestType     icmp.Type
		replyType       icmp.Type
		icmpConn        *icmp.PacketConn
		v4RawConn       *ipv4.RawConn
		hopLimitFlagSet bool = true

		durationGaugeVec = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "probe_icmp_duration_seconds",
			Help: "Duration of icmp request by phase",
		}, []string{"phase"})

		hopLimitGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "probe_icmp_reply_hop_limit",
			Help: "Replied packet hop limit (TTL for ipv4)",
		})
	)

	for _, lv := range []string{"resolve", "setup", "rtt"} {
		durationGaugeVec.WithLabelValues(lv)
	}

	dstIPAddr, lookupTime, err, probeIPProtocolGauge, probeIPAddrHash := chooseProtocol(nil, thisPlugin.IPProtocol, thisPlugin.IPProtocolFallback, target, logger)
	if err != nil {
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)

	var srcIP net.IP
	if len(thisPlugin.sourceIPAddress) > 0 {
		if srcIP = net.ParseIP(thisPlugin.sourceIPAddress); srcIP == nil {
			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", thisPlugin.sourceIPAddress)
			return
		}
		level.Info(logger).Log("msg", "Using source address", "srcIP", srcIP)
	}

	setupStart := time.Now()
	level.Info(logger).Log("msg", "Creating socket")

	privileged := true
	tryUnprivileged := runtime.GOOS == "darwin" || runtime.GOOS == "linux"

	if dstIPAddr.IP.To4() == nil {
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply

		if srcIP == nil {
			srcIP = net.ParseIP("::")
		}

		if tryUnprivileged {
			icmpConn, err = icmp.ListenPacket("udp6", srcIP.String())
			if err != nil {
				level.Debug(logger).Log("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
			} else {
				privileged = false
			}
		}

		if privileged {
			icmpConn, err = icmp.ListenPacket("ip6:ipv6-icmp", srcIP.String())
			if err != nil {
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				return
			}
		}
		defer icmpConn.Close()

		if err := icmpConn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
			level.Debug(logger).Log("msg", "Failed to set Control Message for retrieving Hop Limit", "err", err)
			hopLimitFlagSet = false
		}
	} else {
		requestType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply

		if srcIP == nil {
			srcIP = net.ParseIP("0.0.0.0")
		}

		if thisPlugin.DontFragment {
			netConn, err := net.ListenPacket("ip4:icmp", srcIP.String())
			if err != nil {
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				return
			}
			defer netConn.Close()

			v4RawConn, err = ipv4.NewRawConn(netConn)
			if err != nil {
				level.Error(logger).Log("msg", "Error creating raw connection", "err", err)
				return
			}
			defer v4RawConn.Close()

			if err := v4RawConn.SetControlMessage(ipv4.FlagTTL, true); err != nil {
				level.Debug(logger).Log("msg", "Failed to set Control Message for retrieving TTL", "err", err)
				hopLimitFlagSet = false
			}
		} else {
			if tryUnprivileged {
				icmpConn, err = icmp.ListenPacket("udp4", srcIP.String())
				if err != nil {
					level.Debug(logger).Log("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
				} else {
					privileged = false
				}
			}

			if privileged {
				icmpConn, err = icmp.ListenPacket("ip4:icmp", srcIP.String())
				if err != nil {
					level.Error(logger).Log("msg", "Error listening to socket", "err", err)
					return
				}
			}
			defer icmpConn.Close()

			if err := icmpConn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true); err != nil {
				level.Debug(logger).Log("msg", "Failed to set Control Message for retrieving TTL", "err", err)
				hopLimitFlagSet = false
			}
		}
	}

	var dst net.Addr = dstIPAddr
	if !privileged {
		dst = &net.UDPAddr{IP: dstIPAddr.IP, Zone: dstIPAddr.Zone}
	}

	var data []byte
	if thisPlugin.PayloadSize != 0 {
		data = make([]byte, thisPlugin.PayloadSize)
		copy(data, "Prometheus Blackbox Exporter")
	} else {
		data = []byte("Prometheus Blackbox Exporter")
	}

	durationGaugeVec.WithLabelValues("setup").Add(time.Since(setupStart).Seconds())

	durations = make([]float64, 0, probeCount)
	successCount = 0

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	batchID := r.Intn(1 << 16)
	for i := 0; i < probeCount; i++ {
		body := &icmp.Echo{
			ID:   batchID, // 用独立ID
			Seq:  int(getICMPSequence()),
			Data: []byte("Prometheus Blackbox Exporter"),
		}
		level.Info(logger).Log("msg", "Creating ICMP packet", "seq", body.Seq, "id", body.ID)
		wm := icmp.Message{
			Type: requestType,
			Code: 0,
			Body: body,
		}

		wb, err := wm.Marshal(nil)
		if err != nil {
			level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
			durations = append(durations, 0)
			continue
		}

		rttStart := time.Now()
		if icmpConn != nil {
			ttl := thisPlugin.TTL
			if ttl > 0 {
				if c4 := icmpConn.IPv4PacketConn(); c4 != nil {
					level.Debug(logger).Log("msg", "Setting TTL (IPv4 unprivileged)", "ttl", ttl)
					c4.SetTTL(ttl)
				}
				if c6 := icmpConn.IPv6PacketConn(); c6 != nil {
					level.Debug(logger).Log("msg", "Setting TTL (IPv6 unprivileged)", "ttl", ttl)
					c6.SetHopLimit(ttl)
				}
			}
			_, err = icmpConn.WriteTo(wb, dst)
		} else {
			ttl := thisPlugin.TTL
			if thisPlugin.TTL > 0 {
				level.Debug(logger).Log("msg", "Overriding TTL (raw IPv4)", "ttl", ttl)
				ttl = thisPlugin.TTL
			}
			header := &ipv4.Header{
				Version:  ipv4.Version,
				Len:      ipv4.HeaderLen,
				Protocol: 1,
				TotalLen: ipv4.HeaderLen + len(wb),
				TTL:      ttl,
				Dst:      dstIPAddr.IP,
				Src:      srcIP,
			}
			header.Flags |= ipv4.DontFragment
			err = v4RawConn.WriteTo(header, wb, nil)
		}
		if err != nil {
			level.Warn(logger).Log("msg", "Error writing to socket", "err", err)
			durations = append(durations, 0)
			continue
		}

		wm.Type = replyType
		idUnknown := !privileged && runtime.GOOS == "linux"
		if idUnknown {
			body.ID = 0
		}
		wbReply, err := wm.Marshal(nil)
		if err != nil {
			level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
			durations = append(durations, 0)
			continue
		}
		if idUnknown {
			wbReply[2] = 0
			wbReply[3] = 0
		}

		rb := make([]byte, 65536)
		// 为每次探测设置单独的超时时间
		perProbeTimeout := 2 * time.Second
		deadline := time.Now().Add(perProbeTimeout)
		if icmpConn != nil {
			err = icmpConn.SetReadDeadline(deadline)
		} else {
			err = v4RawConn.SetReadDeadline(deadline)
		}
		if err != nil {
			level.Error(logger).Log("msg", "Error setting socket deadline", "err", err)
			durations = append(durations, 0)
			continue
		}

		level.Info(logger).Log("msg", "Waiting for reply packet", "probe", i+1)
		successProbe := false
		for {
			var n int
			var peer net.Addr
			var err error
			var hopLimit float64 = -1

			if dstIPAddr.IP.To4() == nil {
				var cm *ipv6.ControlMessage
				n, cm, peer, err = icmpConn.IPv6PacketConn().ReadFrom(rb)
				if cm != nil && hopLimitFlagSet {
					hopLimit = float64(cm.HopLimit)
				}
			} else {
				var cm *ipv4.ControlMessage
				if icmpConn != nil {
					n, cm, peer, err = icmpConn.IPv4PacketConn().ReadFrom(rb)
				} else {
					var h *ipv4.Header
					var p []byte
					h, p, cm, err = v4RawConn.ReadFrom(rb)
					if err == nil {
						copy(rb, p)
						n = len(p)
						peer = &net.IPAddr{IP: h.Src}
					}
				}
				if cm != nil && hopLimitFlagSet {
					hopLimit = float64(cm.TTL)
				}
			}
			if err != nil {
				if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
					level.Warn(logger).Log("msg", "Timeout reading from socket", "err", err)
					break
				}
				level.Error(logger).Log("msg", "Error reading from socket", "err", err)
				break
			}
			if peer.String() != dst.String() {
				continue
			}
			if idUnknown {
				rb[4] = 0
				rb[5] = 0
			}
			if idUnknown || replyType == ipv6.ICMPTypeEchoReply {
				rb[2] = 0
				rb[3] = 0
			}
			if bytes.Equal(rb[:n], wbReply) {
				duration := time.Since(rttStart).Seconds()
				durations = append(durations, duration)
				if hopLimit >= 0 {
					hopLimitGauge.Set(hopLimit)
				}
				level.Info(logger).Log("msg", "Found matching reply packet", "probe", i+1)
				successCount++
				successProbe = true
				break
			}
		}
		if !successProbe {
			durations = append(durations, 0)
		}
		// 可选：每次探测间隔一点时间
		time.Sleep(50 * time.Millisecond)
	}

	lossCount = probeCount - successCount
	return
}
