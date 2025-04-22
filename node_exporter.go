// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package node_exporter_main

import (
	"crypto/tls"
	"fmt"
	stdlog "log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/user"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"go.uber.org/zap"

	"github.com/alecthomas/kingpin/v2"
	"github.com/chaolihf/node_exporter/collector"
	"github.com/chaolihf/node_exporter/exporters/dns"
	"github.com/chaolihf/node_exporter/exporters/firewall"
	"github.com/chaolihf/node_exporter/exporters/gpu"
	"github.com/chaolihf/node_exporter/exporters/hadoop"
	"github.com/chaolihf/node_exporter/exporters/icmp"
	"github.com/chaolihf/node_exporter/exporters/switchs"
	jjson "github.com/chaolihf/udpgo/json"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

// handler wraps an unfiltered http.Handler but uses a filtered handler,
// created on the fly, if filtering is requested. Create instances with
// newHandler.
type handler struct {
	unfilteredHandler http.Handler
	// exporterMetricsRegistry is a separate registry for the metrics about
	// the exporter itself.
	exporterMetricsRegistry *prometheus.Registry
	includeExporterMetrics  bool
	maxRequests             int
	logger                  log.Logger
}

var (
	readTimeout            int  = 10
	enableHadoopExporter   bool = false
	enableSwitchExporter   bool = false
	enableFirewallExporter bool = false
	enableBlackBoxExporter bool = false
<<<<<<< HEAD
	enableGpuExporter      bool = false
=======
	enableDnsExporter      bool = false
>>>>>>> 4c7783feaaef2c305f8b4e391c0d2915175ba390
)

func newHandler(includeExporterMetrics bool, maxRequests int, logger log.Logger) *handler {
	h := &handler{
		exporterMetricsRegistry: prometheus.NewRegistry(),
		includeExporterMetrics:  includeExporterMetrics,
		maxRequests:             maxRequests,
		logger:                  logger,
	}
	if h.includeExporterMetrics {
		h.exporterMetricsRegistry.MustRegister(
			promcollectors.NewProcessCollector(promcollectors.ProcessCollectorOpts{}),
			promcollectors.NewGoCollector(),
		)
	}
	if innerHandler, err := h.innerHandler(); err != nil {
		panic(fmt.Sprintf("Couldn't create metrics handler: %s", err))
	} else {
		h.unfilteredHandler = innerHandler
	}
	return h
}

// ServeHTTP implements http.Handler.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	filters := r.URL.Query()["collect[]"]
	level.Debug(h.logger).Log("msg", "collect query:", "filters", filters)

	if len(filters) == 0 {
		// No filters, use the prepared unfiltered handler.
		h.unfilteredHandler.ServeHTTP(w, r)
		return
	}
	// To serve filtered metrics, we create a filtering handler on the fly.
	filteredHandler, err := h.innerHandler(filters...)
	if err != nil {
		level.Warn(h.logger).Log("msg", "Couldn't create filtered metrics handler:", "err", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("Couldn't create filtered metrics handler: %s", err)))
		return
	}
	filteredHandler.ServeHTTP(w, r)
}

// innerHandler is used to create both the one unfiltered http.Handler to be
// wrapped by the outer handler and also the filtered handlers created on the
// fly. The former is accomplished by calling innerHandler without any arguments
// (in which case it will log all the collectors enabled via command-line
// flags).
func (h *handler) innerHandler(filters ...string) (http.Handler, error) {
	nc, err := collector.NewNodeCollector(h.logger, filters...)
	if err != nil {
		return nil, fmt.Errorf("couldn't create collector: %s", err)
	}

	// Only log the creation of an unfiltered handler, which should happen
	// only once upon startup.
	if len(filters) == 0 {
		level.Info(h.logger).Log("msg", "Enabled collectors")
		collectors := []string{}
		for n := range nc.Collectors {
			collectors = append(collectors, n)
		}
		sort.Strings(collectors)
		for _, c := range collectors {
			level.Info(h.logger).Log("collector", c)
		}
	}

	r := prometheus.NewRegistry()
	r.MustRegister(version.NewCollector("node_exporter"))
	if err := r.Register(nc); err != nil {
		return nil, fmt.Errorf("couldn't register node collector: %s", err)
	}
	handler := promhttp.HandlerFor(
		prometheus.Gatherers{h.exporterMetricsRegistry, r},
		promhttp.HandlerOpts{
			ErrorLog:            stdlog.New(log.NewStdlibAdapter(level.Error(h.logger)), "", 0),
			ErrorHandling:       promhttp.ContinueOnError,
			MaxRequestsInFlight: h.maxRequests,
			Registry:            h.exporterMetricsRegistry,
		},
	)
	if h.includeExporterMetrics {
		// Note that we have to use h.exporterMetricsRegistry here to
		// use the same promhttp metrics for all expositions.
		handler = promhttp.InstrumentMetricHandler(
			h.exporterMetricsRegistry, handler,
		)
	}
	return handler, nil
}

func initReadConfig() error {
	filePath := "config.json"
	content, err := os.ReadFile(filePath)
	if err != nil {
		stdlog.Printf("读取文件出错: %s, %v\n", filePath, err)
		return err
	} else {
		jsonConfigInfos, err := jjson.NewJsonObject([]byte(content))
		if err != nil {
			stdlog.Printf("JSON文件格式出错:%s", err)
			return err
		} else {
			readTimeout = jsonConfigInfos.GetInt("readTimeout")
			jsonModuleInfos := jsonConfigInfos.GetJsonArray("module")
			for _, jsonModuleInfo := range jsonModuleInfos {
				if jsonModuleInfo.GetStringValue() == "hadoop_exporter" {
					enableHadoopExporter = true
				} else if jsonModuleInfo.GetStringValue() == "switch_exporter" {
					enableSwitchExporter = true
				} else if jsonModuleInfo.GetStringValue() == "firewall_exporter" {
					enableFirewallExporter = true
				} else if jsonModuleInfo.GetStringValue() == "blackbox_exporter" {
					enableBlackBoxExporter = true
<<<<<<< HEAD
				} else if jsonModuleInfo.GetStringValue() == "gpu_exporter" {
					enableGpuExporter = true
=======
				} else if jsonModuleInfo.GetStringValue() == "dns_exporter" {
					enableDnsExporter = true
>>>>>>> 4c7783feaaef2c305f8b4e391c0d2915175ba390
				}
			}
		}
	}
	return nil
}

func Main(fileLogger *zap.Logger) {

	defer func() {
		fileLogger.Sync()
		if r := recover(); r != nil {
			fileLogger.Info(fmt.Sprintf("node_exporter退出原因:", r))
			fmt.Println("node_exporter退出原因:", r)
		} else {
			fileLogger.Info("node_exporter正常退出")
			fmt.Println("node_exporter正常退出")
		}
	}()

	var (
		//修改默认路径
		metricsPath = kingpin.Flag(
			"web.telemetry-path",
			"Path under which to expose metrics.",
		).Default("/OneAgentMetrics").String()
		disableExporterMetrics = kingpin.Flag(
			"web.disable-exporter-metrics",
			"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
		).Bool()
		//修改默认并发请求数
		maxRequests = kingpin.Flag(
			"web.max-requests",
			"Maximum number of parallel scrape requests. Use 0 to disable.",
		).Default("3").Int()
		disableDefaultCollectors = kingpin.Flag(
			"collector.disable-defaults",
			"Set all collectors to disabled by default.",
		).Default("false").Bool()
		maxProcs = kingpin.Flag(
			"runtime.gomaxprocs", "The target number of CPUs Go will run on (GOMAXPROCS)",
		).Envar("GOMAXPROCS").Default("1").Int()
		toolkitFlags = kingpinflag.AddFlags(kingpin.CommandLine, ":9100")
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("node_exporter"))
	kingpin.CommandLine.UsageWriter(os.Stdout)
	kingpin.HelpFlag.Short('h')
	var params []string
	for _, arg := range os.Args[1:] {
		if arg != "-test.run" && !strings.HasPrefix(arg, "^") {
			params = append(params, arg)
		}
	}
	commands, err := kingpin.CommandLine.Parse(params)
	kingpin.MustParse(commands, err)
	logger := promlog.New(promlogConfig)

	if *disableDefaultCollectors {
		collector.DisableDefaultCollectors()
	}
	level.Info(logger).Log("msg", "Starting node_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())
	if user, err := user.Current(); err == nil && user.Uid == "0" {
		level.Warn(logger).Log("msg", "Node Exporter is running as root user. This exporter is designed to run as unprivileged user, root is not required.")
	}
	runtime.GOMAXPROCS(*maxProcs)
	level.Debug(logger).Log("msg", "Go MAXPROCS", "procs", runtime.GOMAXPROCS(0))

	http.Handle(*metricsPath, newHandler(!*disableExporterMetrics, *maxRequests, logger))
	if *metricsPath != "/" {
		//注释以下代码，不提供等待页面
		// landingConfig := web.LandingConfig{
		// 	Name:        "Node Exporter",
		// 	Description: "Prometheus Node Exporter",
		// 	Version:     version.Info(),
		// 	Links: []web.LandingLinks{
		// 		{
		// 			Address: *metricsPath,
		// 			Text:    "Metrics",
		// 		},
		// 	},
		// }
		// landingPage, err := web.NewLandingPage(landingConfig)
		// if err != nil {
		// 	level.Error(logger).Log("err", err)
		// 	os.Exit(1)
		// }
		// http.Handle("/", landingPage)
	}

	err = initReadConfig()
	if err != nil {
		level.Info(logger).Log("msg", "Reading config.json err:", err)
	}
	if enableHadoopExporter {
		_, err = os.Stat("hadoopConfig.json")
		if err == nil {
			http.HandleFunc("/hadoopMetrics", func(w http.ResponseWriter, r *http.Request) {
				hadoop.RequestHandler(w, r)
			})
		}
		hadoop.SetLogger(logger)
	}
	if enableSwitchExporter {
		http.HandleFunc("/switchMetrics", func(w http.ResponseWriter, r *http.Request) {
			switchs.RequestHandler(w, r)
		})
		switchs.SetLogger(logger)
	}
	if enableFirewallExporter {
		http.HandleFunc("/firewallMetrics", func(w http.ResponseWriter, r *http.Request) {
			firewall.RequestHandler(w, r)
		})
		firewall.SetLogger(logger)
	}
	if enableBlackBoxExporter {
		http.HandleFunc("/icmpMetrics", func(w http.ResponseWriter, r *http.Request) {
			icmp.RequestHandler(w, r)
		})
		icmp.SetLogger(logger)
	}
<<<<<<< HEAD
	if enableGpuExporter {
		http.HandleFunc("/gpuMetrics", func(w http.ResponseWriter, r *http.Request) {
			gpu.RequestHandler(w, r)
		})
		gpu.SetLogger(logger)
=======
	if enableDnsExporter {
		http.HandleFunc("/dnsMetrics", func(w http.ResponseWriter, r *http.Request) {
			dns.RequestHandler(w, r)
		})
		dns.SetLogger(logger)
>>>>>>> 4c7783feaaef2c305f8b4e391c0d2915175ba390
	}

	tlsconf := &tls.Config{
		InsecureSkipVerify:       true,
		MaxVersion:               tls.VersionTLS13,
		MinVersion:               tls.VersionTLS12,
		PreferServerCipherSuites: true,
	}
	//维护到配置文件
	tlsconf.CipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	}

	server := &http.Server{
		ReadTimeout: time.Duration(readTimeout) * time.Second,
		TLSConfig:   tlsconf,
	}
	if err := web.ListenAndServe(server, toolkitFlags, logger); err != nil {
		level.Error(logger).Log("err", err)
		os.Exit(1)
	}
}
