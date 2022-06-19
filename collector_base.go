package main

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

var collectorGlobal CollectorGlobal

type CollectorBase struct {
	Name       string
	scrapeTime *time.Duration

	logger *log.Entry

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
	c.logger = log.WithField("collector", c.Name)
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
		c.logger.Info("starting metrics collection")
	}
}

func (c *CollectorBase) collectionFinish() {
	duration := time.Since(c.collectionStartTime)
	c.LastScrapeDuration = &duration

	if !c.isHidden {
		c.logger.WithField("duration", c.LastScrapeDuration.Seconds()).Infof("finished metrics collection (duration: %v)", c.LastScrapeDuration)
	}
}

func (c *CollectorBase) sleepUntilNextCollection() {
	if !c.isHidden {
		c.logger.Debugf("sleeping %v", c.GetScrapeTime().String())
	}
	time.Sleep(*c.GetScrapeTime())
}
