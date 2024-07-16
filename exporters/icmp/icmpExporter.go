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
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/chaolihf/node_exporter/pkg/clients/sshclient"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var logger log.Logger

type icmpCollector struct {
	TargetName string
}

var (
	icmpID            int
	icmpSequence      uint16
	icmpSequenceMutex sync.Mutex
	//DefaultICMPTTL    = 64
)

var isIcmpInited = false

func SetLogger(globalLogger log.Logger) {
	if !isIcmpInited {
		logger = globalLogger
		sshclient.SetLogger(globalLogger)
		isIcmpInited = true
	}
}

func RequestHandler(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query()
	registry := prometheus.NewRegistry()
	targetName := params.Get("target")
	if targetName == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing target parameter!"))
		return
	}
	registry.MustRegister(&icmpCollector{TargetName: targetName})
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func (collector *icmpCollector) Describe(ch chan<- *prometheus.Desc) {

}

func (collector *icmpCollector) Collect(ch chan<- prometheus.Metric) {
	metrics := getIcmpResult(collector.TargetName)
	for _, metric := range metrics {
		ch <- metric
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

var plugin *ICMPScriptPlugin

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

// 完成网络指标的获取和拼装
func getIcmpResult(targetName string) []prometheus.Metric {
	var metrics []prometheus.Metric
	//确定是否探测成功指标
	probeSuccessGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_success",
		Help: "Displays whether or not the probe was a success",
	})
	//确定探测耗时指标
	probeDurationGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_duration_seconds",
		Help: "Returns how long the probe took to complete in seconds",
	})
	//确定丢包率指标
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
	//起始时间
	start := time.Now()
	//初始化整型变量n，计算丢包数
	n := 0
	//定义一个时间切片用于记录四次探测耗费的时间
	var durationSecondSlice []float64
	//发送4个数据包并计算相关指标
	for i := 0; i < 4; i++ {
		//记录探测开始时间
		everyStart := time.Now()
		//若探测不成功发生丢包(探测时将获取到的三个指标放入resistry)
		if !ProbeICMP(plugin, targetName, metrics) {
			n++
		}
		//记录探测结束时间
		everyEnd := time.Since(everyStart).Seconds()
		//记录该次探测耗费时间
		durationSecondSlice = append(durationSecondSlice, everyEnd)
	}
	//获取该次探测经历的时间(该时间为总时间，计算其平均值)
	probeDurationGauge.Set(time.Since(start).Seconds() / 4)
	//根据丢包数量计算丢包率
	probeLossGauge.Set(float64(n+1) / 4)
	//获取四次探测耗时的极值
	sort.Float64s(durationSecondSlice)
	probeMinDurationGauge.Set(durationSecondSlice[0])
	probeMaxDurationGauge.Set(durationSecondSlice[len(durationSecondSlice)-1])
	//若丢包数小于4则探测成功
	if n < 4 {
		probeSuccessGauge.Set(1)
	} else {
		probeSuccessGauge.Set(0)
	}
	metrics = append(metrics, probeSuccessGauge)
	metrics = append(metrics, probeDurationGauge)
	metrics = append(metrics, probeLossGauge)
	metrics = append(metrics, probeMinDurationGauge)
	metrics = append(metrics, probeMaxDurationGauge)
	return metrics
}

// 初始化配置文件
func init() {
	//初始化ICMP采集配置
	plugin = NewICMPScriptPlugin(logger)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// PID is typically 1 when running in a container; in that case, set
	// the ICMP echo ID to a random value to avoid potential clashes with
	// other blackbox_exporter instances. See #411.
	if pid := os.Getpid(); pid == 1 {
		icmpID = r.Intn(1 << 16)
	} else {
		icmpID = pid & 0xffff
	}

	// Start the ICMP echo sequence at a random offset to prevent them from
	// being in sync when several blackbox_exporter instances are restarted
	// at the same time. See #411.
	icmpSequence = uint16(r.Intn(1 << 16))
}

func ProbeICMP(thisPlugin *ICMPScriptPlugin, target string, metrics []prometheus.Metric) (success bool) {
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

	//logger := thisPlugin.logger

	ctx, _ := context.WithDeadline(context.Background(),
		time.Now().Add(time.Duration(thisPlugin.Deadline)*time.Second))

	for _, lv := range []string{"resolve", "setup", "rtt"} {
		durationGaugeVec.WithLabelValues(lv)
		//metrics = append(metrics, durationGaugeVec.WithLabelValues(lv))
	}

	//registry.MustRegister(durationGaugeVec)

	dstIPAddr, lookupTime, err := chooseProtocol(nil, thisPlugin.IPProtocol, thisPlugin.IPProtocolFallback, target, metrics, logger)

	if err != nil {
		//logger.Error(fmt.Sprint("msg", "Error resolving address", err))
		level.Error(logger).Log("msg", "Error resolving address", "err", err)
		return false
	}
	durationGaugeVec.WithLabelValues("resolve").Add(lookupTime)

	var srcIP net.IP
	if len(thisPlugin.sourceIPAddress) > 0 {
		if srcIP = net.ParseIP(thisPlugin.sourceIPAddress); srcIP == nil {
			//logger.Error(fmt.Sprint("msg", "Error parsing source ip address", "srcIP", thisPlugin.sourceIPAddress))
			level.Error(logger).Log("msg", "Error parsing source ip address", "srcIP", thisPlugin.sourceIPAddress)
			return false
		}
		//logger.Info(fmt.Sprint("msg", "Using source address", "srcIP", srcIP))
		level.Info(logger).Log("msg", "Using source address", "srcIP", srcIP)
	}

	setupStart := time.Now()
	//logger.Info(fmt.Sprint("msg", "Creating socket"))
	level.Info(logger).Log("msg", "Creating socket")

	privileged := true
	// Unprivileged sockets are supported on Darwin and Linux only.
	tryUnprivileged := runtime.GOOS == "darwin" || runtime.GOOS == "linux"

	if dstIPAddr.IP.To4() == nil {
		requestType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply

		if srcIP == nil {
			srcIP = net.ParseIP("::")
		}

		if tryUnprivileged {
			// "udp" here means unprivileged -- not the protocol "udp".
			icmpConn, err = icmp.ListenPacket("udp6", srcIP.String())
			if err != nil {
				//logger.Debug(fmt.Sprint("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err))
				level.Debug(logger).Log("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
			} else {
				privileged = false
			}
		}

		if privileged {
			icmpConn, err = icmp.ListenPacket("ip6:ipv6-icmp", srcIP.String())
			if err != nil {
				//logger.Error(fmt.Sprint("msg", "Error listening to socket", "err", err))
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				return
			}
		}
		defer icmpConn.Close()

		if err := icmpConn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
			//logger.Error(fmt.Sprint("msg", "Failed to set Control Message for retrieving Hop Limit", "err", err))
			level.Error(logger).Log("msg", "Failed to set Control Message for retrieving Hop Limit", "err", err)
			hopLimitFlagSet = false
		}
	} else {
		requestType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply

		if srcIP == nil {
			srcIP = net.ParseIP("0.0.0.0")
		}

		if thisPlugin.DontFragment {
			// If the user has set the don't fragment option we cannot use unprivileged
			// sockets as it is not possible to set IP header level options.
			netConn, err := net.ListenPacket("ip4:icmp", srcIP.String())
			if err != nil {
				//logger.Error(fmt.Sprint("msg", "Error listening to socket", "err", err))
				level.Error(logger).Log("msg", "Error listening to socket", "err", err)
				return
			}
			defer netConn.Close()

			v4RawConn, err = ipv4.NewRawConn(netConn)
			if err != nil {
				//logger.Error(fmt.Sprint("msg", "Error creating raw connection", "err", err))
				level.Error(logger).Log("msg", "Error creating raw connection", "err", err)
				return
			}
			defer v4RawConn.Close()

			if err := v4RawConn.SetControlMessage(ipv4.FlagTTL, true); err != nil {
				//logger.Error(fmt.Sprint("msg", "Failed to set Control Message for retrieving TTL", "err", err))
				level.Error(logger).Log("msg", "Failed to set Control Message for retrieving TTL", "err", err)
				hopLimitFlagSet = false
			}
		} else {
			if tryUnprivileged {
				icmpConn, err = icmp.ListenPacket("udp4", srcIP.String())
				if err != nil {
					//logger.Debug(fmt.Sprint("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err))
					level.Debug(logger).Log("msg", "Unable to do unprivileged listen on socket, will attempt privileged", "err", err)
				} else {
					privileged = false
				}
			}

			if privileged {
				icmpConn, err = icmp.ListenPacket("ip4:icmp", srcIP.String())
				if err != nil {
					//logger.Error(fmt.Sprint("msg", "Error listening to socket", "err", err))
					level.Error(logger).Log("msg", "Error listening to socket", "err", err)
					return
				}
			}
			defer icmpConn.Close()

			if err := icmpConn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true); err != nil {
				//logger.Debug(fmt.Sprint("msg", "Failed to set Control Message for retrieving TTL", "err", err))
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

	body := &icmp.Echo{
		ID:   icmpID,
		Seq:  int(getICMPSequence()),
		Data: data,
	}
	//logger.Info(fmt.Sprint("msg", "Creating ICMP packet", "seq", body.Seq, "id", body.ID))
	level.Info(logger).Log("msg", "Creating ICMP packet", "seq", body.Seq, "id", body.ID)

	wm := icmp.Message{
		Type: requestType,
		Code: 0,
		Body: body,
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		//logger.Error(fmt.Sprint("msg", "Error marshalling packet", "err", err))
		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
		return
	}

	durationGaugeVec.WithLabelValues("setup").Add(time.Since(setupStart).Seconds())
	//logger.Info(fmt.Sprint("msg", "Writing out packet"))
	level.Info(logger).Log("msg", "Writing out packet")
	rttStart := time.Now()

	if icmpConn != nil {
		ttl := thisPlugin.TTL
		if ttl > 0 {
			if c4 := icmpConn.IPv4PacketConn(); c4 != nil {
				//logger.Debug(fmt.Sprint("msg", "Setting TTL (IPv4 unprivileged)", "ttl", ttl))
				level.Debug(logger).Log("msg", "Setting TTL (IPv4 unprivileged)", "ttl", ttl)
				c4.SetTTL(ttl)
			}
			if c6 := icmpConn.IPv6PacketConn(); c6 != nil {
				//logger.Debug(fmt.Sprint("msg", "Setting TTL (IPv6 unprivileged)", "ttl", ttl))
				level.Debug(logger).Log("msg", "Setting TTL (IPv6 unprivileged)", "ttl", ttl)
				c6.SetHopLimit(ttl)
			}
		}
		_, err = icmpConn.WriteTo(wb, dst)
	} else {
		ttl := DefaultICMPTTL
		if thisPlugin.TTL > 0 {
			//logger.Debug(fmt.Sprint("msg", "Overriding TTL (raw IPv4)", "ttl", ttl))
			level.Debug(logger).Log("msg", "Overriding TTL (raw IPv4)", "ttl", ttl)
			ttl = thisPlugin.TTL
		}
		// Only for IPv4 raw. Needed for setting DontFragment flag.
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
		//logger.Warn(fmt.Sprint("msg", "Error writing to socket", "err", err))
		level.Warn(logger).Log("msg", "Error writing to socket", "err", err)
		return
	}

	// Reply should be the same except for the message type and ID if
	// unprivileged sockets were used and the kernel used its own.
	wm.Type = replyType
	// Unprivileged cannot set IDs on Linux.
	idUnknown := !privileged && runtime.GOOS == "linux"
	if idUnknown {
		body.ID = 0
	}
	wb, err = wm.Marshal(nil)
	if err != nil {
		//logger.Error(fmt.Sprint("msg", "Error marshalling packet", "err", err))
		level.Error(logger).Log("msg", "Error marshalling packet", "err", err)
		return
	}

	if idUnknown {
		// If the ID is unknown (due to unprivileged sockets) we also cannot know
		// the checksum in userspace.
		wb[2] = 0
		wb[3] = 0
	}

	rb := make([]byte, 65536)
	deadline, _ := ctx.Deadline()
	if icmpConn != nil {
		err = icmpConn.SetReadDeadline(deadline)
	} else {
		err = v4RawConn.SetReadDeadline(deadline)
	}
	if err != nil {
		//logger.Error(fmt.Sprint("msg", "Error setting socket deadline", "err", err))
		level.Error(logger).Log("msg", "Error setting socket deadline", "err", err)
		return
	}
	//logger.Info(fmt.Sprint("msg", "Waiting for reply packets"))
	level.Info(logger).Log("msg", "Waiting for reply packets")
	for {
		var n int
		var peer net.Addr
		var err error
		var hopLimit float64 = -1

		if dstIPAddr.IP.To4() == nil {
			var cm *ipv6.ControlMessage
			n, cm, peer, err = icmpConn.IPv6PacketConn().ReadFrom(rb)
			// HopLimit == 0 is valid for IPv6, although go initialize it as 0.
			if cm != nil && hopLimitFlagSet {
				hopLimit = float64(cm.HopLimit)
			} else {
				//logger.Debug(fmt.Sprint("msg", "Cannot get Hop Limit from the received packet. 'probe_icmp_reply_hop_limit' will be missing."))
				level.Debug(logger).Log("msg", "Cannot get Hop Limit from the received packet. 'probe_icmp_reply_hop_limit' will be missing.")
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
				// Not really Hop Limit, but it is in practice.
				hopLimit = float64(cm.TTL)
			} else {
				//logger.Debug(fmt.Sprint("msg", "Cannot get TTL from the received packet. 'probe_icmp_reply_hop_limit' will be missing."))
				level.Debug(logger).Log("msg", "Cannot get TTL from the received packet. 'probe_icmp_reply_hop_limit' will be missing.")
			}
		}
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				//logger.Warn(fmt.Sprint("msg", "Timeout reading from socket", "err", err))
				level.Warn(logger).Log("msg", "Timeout reading from socket", "err", err)
				return
			}
			//logger.Error(fmt.Sprint("msg", "Error reading from socket", "err", err))
			level.Error(logger).Log("msg", "Error reading from socket", "err", err)
			continue
		}
		if peer.String() != dst.String() {
			continue
		}
		if idUnknown {
			// Clear the ID from the packet, as the kernel will have replaced it (and
			// kept track of our packet for us, hence clearing is safe).
			rb[4] = 0
			rb[5] = 0
		}
		if idUnknown || replyType == ipv6.ICMPTypeEchoReply {
			// Clear checksum to make comparison succeed.
			rb[2] = 0
			rb[3] = 0
		}
		if bytes.Equal(rb[:n], wb) {
			durationGaugeVec.WithLabelValues("rtt").Add(time.Since(rttStart).Seconds())
			if hopLimit >= 0 {
				hopLimitGauge.Set(hopLimit)
				//registry.MustRegister(hopLimitGauge)
				//metrics = append(metrics, hopLimitGauge)
			}
			//logger.Info(fmt.Sprint("msg", "Found matching reply packet"))
			level.Info(logger).Log("msg", "Found matching reply packet")
			return true
		}
	}
}
