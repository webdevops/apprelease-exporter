package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/webdevops/apprelease-exporter/config"
	"net/http"
	"os"
	"path"
	"runtime"
	"strings"
	"time"
)

const (
	Author = "webdevops.io"
)

var (
	argparser *flags.Parser
	opts      config.Opts

	collectorList map[string]*CollectorGeneral
	AppConfig     Config

	// Git version information
	gitCommit = "<unknown>"
	gitTag    = "<unknown>"
)

func main() {
	initArgparser()

	log.Infof("starting apprelease-exporter v%s (%s; %s; by %v)", gitTag, gitCommit, runtime.Version(), Author)
	log.Info(string(opts.GetJson()))

	log.Infof("loading config")
	readConfig()

	log.Infof("starting metrics collection")

	if opts.Cache.Path != "" {
		log.Infof("enable cache (path: %v, ttl: %v)", opts.Cache.Path, opts.Cache.Ttl.String())
	}

	if opts.Cve.Url != "" {
		log.Infof("enable CVE fetching")
	}

	initMetricCollector()

	log.Infof("starting http server on %s", opts.ServerBind)
	startHttpServer()
}

// init argparser and parse/validate arguments
func initArgparser() {
	argparser = flags.NewParser(&opts, flags.Default)
	_, err := argparser.Parse()

	// check if there is an parse error
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		} else {
			fmt.Println(err)
			fmt.Println()
			argparser.WriteHelp(os.Stdout)
			os.Exit(1)
		}
	}

	// verbose level
	if opts.Logger.Verbose {
		log.SetLevel(log.DebugLevel)
	}

	// debug level
	if opts.Logger.Debug {
		log.SetReportCaller(true)
		log.SetLevel(log.TraceLevel)
		log.SetFormatter(&log.TextFormatter{
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				s := strings.Split(f.Function, ".")
				funcName := s[len(s)-1]
				return funcName, fmt.Sprintf("%s:%d", path.Base(f.File), f.Line)
			},
		})
	}

	// json log format
	if opts.Logger.LogJson {
		log.SetReportCaller(true)
		log.SetFormatter(&log.JSONFormatter{
			DisableTimestamp: true,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				s := strings.Split(f.Function, ".")
				funcName := s[len(s)-1]
				return funcName, fmt.Sprintf("%s:%d", path.Base(f.File), f.Line)
			},
		})
	}

	if opts.Scrape.TimeDocker == nil {
		opts.Scrape.TimeDocker = &opts.Scrape.Time
	}

	if opts.Scrape.TimeGithub == nil {
		opts.Scrape.TimeGithub = &opts.Scrape.Time
	}
}

func readConfig() {
	AppConfig = NewAppConfig(opts.Config.Path)
}

func initMetricCollector() {
	var collectorName string
	collectorList = map[string]*CollectorGeneral{}

	collectorName = "docker"
	if opts.Scrape.TimeDocker.Seconds() > 0 {
		collectorList[collectorName] = NewCollectorGeneral(collectorName, &MetricsCollectorDocker{})
		collectorList[collectorName].Setup(*opts.Scrape.TimeDocker)
	}

	collectorName = "github"
	if opts.Scrape.TimeGithub.Seconds() > 0 {
		collectorList[collectorName] = NewCollectorGeneral(collectorName, &MetricsCollectorGithub{})
		collectorList[collectorName].Setup(*opts.Scrape.TimeGithub)
	}

	for _, collector := range collectorList {
		collector.Run()
	}

	collector := NewCollectorGeneral("Collector", &MetricsCollectorCollector{})
	collector.Setup(time.Duration(10 * time.Second))
	collector.SetIsHidden(true)
	collector.Run()
}

// start and handle prometheus handler
func startHttpServer() {
	http.Handle("/metrics", promhttp.Handler())
	log.Fatal(http.ListenAndServe(opts.ServerBind, nil))
}
