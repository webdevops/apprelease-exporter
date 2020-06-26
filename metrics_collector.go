package main

import (
	"context"
	"github.com/prometheus/client_golang/prometheus"
	"time"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
)

type (
	MetricsCollectorCollector struct {
		CollectorProcessorGeneral
	}

	AppreleaseVersion struct {
		Tag       string
		Version   string
		CreatedAt *time.Time
	}
)

func (m *MetricsCollectorCollector) Setup(collector *CollectorGeneral) {
	m.CollectorReference = collector
}

func (m *MetricsCollectorCollector) Reset() {
}

func (m *MetricsCollectorCollector) Collect(ctx context.Context, callback chan<- func()) {
	m.collectCollectorStats(ctx, callback)
}

func (m *MetricsCollectorCollector) collectCollectorStats(ctx context.Context, callback chan<- func()) {
	statsMetrics := prometheusCommon.NewMetricsList()

	for _, collector := range collectorList {
		if collector.LastScrapeDuration != nil {
			statsMetrics.AddDuration(prometheus.Labels{
				"name": collector.Name,
				"type": "collectorDuration",
			}, *collector.LastScrapeDuration)
		}
	}

	callback <- func() {
		statsMetrics.GaugeSet(m.CollectorReference.PrometheusStatsGauge())
	}
}
