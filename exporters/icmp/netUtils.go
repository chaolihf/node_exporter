package icmp

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var protocolToGauge = map[string]float64{
	"ip4": 4,
	"ip6": 6,
}

// Returns the IP for the IPProtocol and lookup time.
func chooseProtocol(ctx context.Context, IPProtocol string, fallbackIPProtocol bool, target string, metrics []prometheus.Metric) (ip *net.IPAddr, lookupTime float64, err error) {
	var fallbackProtocol string
	probeDNSLookupTimeSeconds := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_dns_lookup_time_seconds",
		Help: "Returns the time taken for probe dns lookup in seconds",
	})

	probeIPProtocolGauge := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_protocol",
		Help: "Specifies whether probe ip protocol is IP4 or IP6",
	})

	probeIPAddrHash := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "probe_ip_addr_hash",
		Help: "Specifies the hash of IP address. It's useful to detect if the IP address changes.",
	})
	//registry用于记录三个指标并返回

	if IPProtocol == "ip6" || IPProtocol == "" {
		IPProtocol = "ip6"
		fallbackProtocol = "ip4"
	} else {
		IPProtocol = "ip4"
		fallbackProtocol = "ip6"
	}

	//logger.Info(fmt.Sprint("msg", "Resolving target address", "target", target, "ip_protocol", IPProtocol))
	resolveStart := time.Now()

	defer func() {
		lookupTime = time.Since(resolveStart).Seconds()
		probeDNSLookupTimeSeconds.Add(lookupTime)
		metrics = append(metrics, probeDNSLookupTimeSeconds)
	}()

	resolver := &net.Resolver{}
	if !fallbackIPProtocol {
		ips, err := resolver.LookupIP(ctx, IPProtocol, target)
		if err == nil {
			for _, ip := range ips {
				//logger.Info(fmt.Sprint("msg", "Resolved target address", "target", target, "ip", ip.String()))
				probeIPProtocolGauge.Set(protocolToGauge[IPProtocol])
				probeIPAddrHash.Set(ipHash(ip))
				metrics = append(metrics, probeIPProtocolGauge)
				metrics = append(metrics, probeIPAddrHash)
				return &net.IPAddr{IP: ip}, lookupTime, nil
			}
		}
		//logger.Error(fmt.Sprint("msg", "Resolution with IP protocol failed", "target", target, "ip_protocol", IPProtocol, "err", err))
		return nil, 0.0, err
	}

	ips, err := resolver.LookupIPAddr(ctx, target)
	if err != nil {
		//logger.Error(fmt.Sprint("msg", "Resolution with IP protocol failed", "target", target, "err", err))
		return nil, 0.0, err
	}

	// Return the IP in the requested protocol.
	var fallback *net.IPAddr
	for _, ip := range ips {
		switch IPProtocol {
		case "ip4":
			if ip.IP.To4() != nil {
				//logger.Info(fmt.Sprint("msg", "Resolved target address", "target", target, "ip", ip.String()))
				probeIPProtocolGauge.Set(4)
				probeIPAddrHash.Set(ipHash(ip.IP))
				metrics = append(metrics, probeIPProtocolGauge)
				metrics = append(metrics, probeIPAddrHash)
				return &ip, lookupTime, nil
			}

			// ip4 as fallback
			fallback = &ip

		case "ip6":
			if ip.IP.To4() == nil {
				//logger.Info(fmt.Sprint("msg", "Resolved target address", "target", target, "ip", ip.String()))
				probeIPProtocolGauge.Set(6)
				probeIPAddrHash.Set(ipHash(ip.IP))
				metrics = append(metrics, probeIPProtocolGauge)
				metrics = append(metrics, probeIPAddrHash)
				return &ip, lookupTime, nil
			}

			// ip6 as fallback
			fallback = &ip
		}
	}

	// Unable to find ip and no fallback set.
	if fallback == nil || !fallbackIPProtocol {
		return nil, 0.0, fmt.Errorf("unable to find ip; no fallback")
	}

	// Use fallback ip protocol.
	if fallbackProtocol == "ip4" {
		probeIPProtocolGauge.Set(4)
	} else {
		probeIPProtocolGauge.Set(6)
	}
	probeIPAddrHash.Set(ipHash(fallback.IP))
	//logger.Info(fmt.Sprint("msg", "Resolved target address", "target", target, "ip", fallback.String()))
	metrics = append(metrics, probeIPProtocolGauge)
	metrics = append(metrics, probeIPAddrHash)
	return fallback, lookupTime, nil
}

func ipHash(ip net.IP) float64 {
	h := fnv.New32a()
	if ip.To4() != nil {
		h.Write(ip.To4())
	} else {
		h.Write(ip.To16())
	}
	return float64(h.Sum32())
}
