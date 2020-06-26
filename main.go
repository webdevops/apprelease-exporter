package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	Author  = "webdevops.io"
)

var (
	argparser *flags.Parser
	Verbose   bool
	Logger    *DaemonLogger

	collectorList map[string]*CollectorGeneral
	AppConfig     Config

	// Git version information
	gitCommit = "<unknown>"
	gitTag    = "<unknown>"
)

var opts struct {
	// general settings
	Verbose    []bool `long:"verbose" short:"v"  env:"VERBOSE"  description:"Verbose mode"`
	ConfigPath string `long:"config" short:"c"  env:"CONFIG"   description:"Config path" required:"true"`

	// server settings
	ServerBind string `long:"bind"  env:"SERVER_BIND"  description:"Server address"  default:":8080"`

	// scrape times
	ScrapeTime       time.Duration  `long:"scrape-time"         env:"SCRAPE_TIME"           description:"Default scrape time (time.duration)"       default:"12h"`
	ScrapeTimeDocker *time.Duration `long:"scrape-time.docker"  env:"SCRAPE_TIME_DOCKER"    description:"Scrape time for Docker (time.duration)"`
	ScrapeTimeGithub *time.Duration `long:"scrape-time.github"  env:"SCRAPE_TIME_GITHUB"    description:"Scrape time for Github (time.duration)"`

	// settings
	DisableCve bool `long:"disable.cve"  env:"DISABLE_CVE"    description:"Disable CVE reports"`

	// github
	GithubPersonalAccessToken *string       `long:"github.personalaccesstoken"  env:"GITHUB_PERSONALACCESSTOKEN" description:"GitHub personal access token"`
	GithubScrapeWait          time.Duration `long:"github.scrape-wait"  env:"GITHUB_SCRAPEWAIT" description:"Wait number between project waits" default:"2s"`
	GithubLimit               int           `long:"github.limit"  env:"GITHUB_LIMIT" description:"Number of results fetched from GitHub" default:"25"`

	//docker
	DockerLimit int `long:"docker.limit"  env:"DOCKER_LIMIT" description:"Number of tags fetched from Docker" default:"25"`

	// cache
	CachePath string        `long:"cache.path"  env:"CACHE_PATH"  description:"Cache path"`
	CacheTtl  time.Duration `long:"cache.ttl"   env:"CACHE_TTL"   description:"Cache expiry" default:"24h"`
}

func main() {
	initArgparser()

	// set verbosity
	Verbose = len(opts.Verbose) >= 1

	Logger = NewLogger(log.Lshortfile, Verbose)
	defer Logger.Close()

	// set verbosity
	Verbose = len(opts.Verbose) >= 1

	Logger.Infof("Init AppRelease exporter v%s (%v; written by %v)", gitTag, gitCommit, Author)
	readConfig()

	Logger.Infof("Starting metrics collection")
	Logger.Infof("  scape time: %v", opts.ScrapeTime)

	if opts.CachePath != "" {
		Logger.Infof("  cache path: %v", opts.CachePath)
		Logger.Infof("   cache ttl: %v", opts.CacheTtl.String())
	}

	if opts.DisableCve {
		Logger.Infof("  cve report: disabled")
	} else {
		Logger.Infof("  cve report: enabled")
	}

	initMetricCollector()

	Logger.Infof("Starting http server on %s", opts.ServerBind)
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

	if opts.ScrapeTimeDocker == nil {
		opts.ScrapeTimeDocker = &opts.ScrapeTime
	}

	if opts.ScrapeTimeGithub == nil {
		opts.ScrapeTimeGithub = &opts.ScrapeTime
	}
}

func readConfig() {
	AppConfig = NewAppConfig(opts.ConfigPath)
}

func initMetricCollector() {
	var collectorName string
	collectorList = map[string]*CollectorGeneral{}

	collectorName = "docker"
	if opts.ScrapeTimeDocker.Seconds() > 0 {
		collectorList[collectorName] = NewCollectorGeneral(collectorName, &MetricsCollectorDocker{})
		collectorList[collectorName].Setup(*opts.ScrapeTimeDocker)
	} else {
		Logger.Infof("collector[%s]: disabled", collectorName)
	}

	collectorName = "github"
	if opts.ScrapeTimeGithub.Seconds() > 0 {
		collectorList[collectorName] = NewCollectorGeneral(collectorName, &MetricsCollectorGithub{})
		collectorList[collectorName].Setup(*opts.ScrapeTimeGithub)
	} else {
		Logger.Infof("collector[%s]: disabled", collectorName)
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
	Logger.Fatal(http.ListenAndServe(opts.ServerBind, nil))
}
