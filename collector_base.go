package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

var collectorGlobal CollectorGlobal

type CollectorBase struct {
	Name       string
	scrapeTime *time.Duration

	LastScrapeDuration  *time.Duration
	collectionStartTime time.Time

	isHidden bool
}

type CollectorGlobal struct {
	prometheus struct {
		stats      *prometheus.GaugeVec
		statsMutex sync.Mutex

		api      *prometheus.CounterVec
		apiMutex sync.Mutex
	}
}

func (c *CollectorBase) Init() {
	c.isHidden = false
}

func (c *CollectorBase) SetScrapeTime(scrapeTime time.Duration) {
	c.scrapeTime = &scrapeTime
}

func (c *CollectorBase) GetScrapeTime() *time.Duration {
	return c.scrapeTime
}

func (c *CollectorBase) SetIsHidden(v bool) {
	c.isHidden = v
}

func (c *CollectorBase) PrometheusStatsGauge() *prometheus.GaugeVec {
	if collectorGlobal.prometheus.stats == nil {
		collectorGlobal.prometheus.statsMutex.Lock()

		collectorGlobal.prometheus.stats = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "apprelease_stats",
				Help: "AppRelease exporter statistics",
			},
			[]string{
				"name",
				"type",
			},
		)

		prometheus.MustRegister(collectorGlobal.prometheus.stats)
		collectorGlobal.prometheus.statsMutex.Unlock()
	}

	return collectorGlobal.prometheus.stats
}

func (c *CollectorBase) collectionStart() {
	c.collectionStartTime = time.Now()

	if !c.isHidden {
		Logger.Infof("collector[%s]: starting metrics collection", c.Name)
	}
}

func (c *CollectorBase) collectionFinish() {
	duration := time.Since(c.collectionStartTime)
	c.LastScrapeDuration = &duration

	if !c.isHidden {
		Logger.Infof("collector[%s]: finished metrics collection (duration: %v)", c.Name, c.LastScrapeDuration)
	}
}

func (c *CollectorBase) sleepUntilNextCollection() {
	if !c.isHidden {
		Logger.Verbosef("collector[%s]: sleeping %v", c.Name, c.GetScrapeTime().String())
	}
	time.Sleep(*c.GetScrapeTime())
}
