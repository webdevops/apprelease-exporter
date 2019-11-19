package main

import (
	"context"
	"encoding/json"
	"facette.io/natsort"
	"fmt"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/prometheus/client_golang/prometheus"
	"sync"
	"time"
)

type (
	MetricsCollectorDocker struct {
		CollectorProcessorGeneral

		client    map[string]*registry.Registry
		cveClient *CveClient

		prometheus struct {
			release    *prometheus.GaugeVec
			releaseCve *prometheus.GaugeVec
		}
	}

	dockerManifestv1Compatibility struct {
		ID      string    `json:"id"`
		Created time.Time `json:"created"`
	}
)

func (m *MetricsCollectorDocker) Setup(collector *CollectorGeneral) {
	m.CollectorReference = collector

	m.client = map[string]*registry.Registry{}
	for _, project := range AppConfig.Projects.Docker {
		registryUrl, username, password := project.GetRegistry()

		if _, ok := m.client[registryUrl]; !ok {
			dockerClient, err := registry.New(registryUrl, username, password)
			if err != nil {
				panic(err)
			}
			dockerClient.Logf = func(format string, args ...interface{}) {
				if Verbose {
					Logger.InfoDepth(1, fmt.Sprintf(format, args...))
				}
			}
			m.client[registryUrl] = dockerClient
		}
	}

	m.cveClient = NewCveClient()

	m.prometheus.release = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apprelease_project_docker_release",
			Help: "AppRelease project docker information",
		},
		[]string{
			"name",
			"image",
			"tag",
			"marked",
		},
	)

	m.prometheus.releaseCve = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apprelease_project_docker_release_cve",
			Help: "AppRelease project docker cve reports",
		},
		[]string{
			"name",
			"image",
			"tag",
			"cve",
		},
	)

	prometheus.MustRegister(m.prometheus.release)
	prometheus.MustRegister(m.prometheus.releaseCve)
}

func (m *MetricsCollectorDocker) Reset() {
	m.prometheus.release.Reset()
	m.prometheus.releaseCve.Reset()
}

func (m *MetricsCollectorDocker) Collect(ctx context.Context, callback chan<- func()) {
	var wg sync.WaitGroup
	for _, project := range AppConfig.Projects.Docker {
		wg.Add(1)
		go func(project ConfigProjectDocker) {
			defer wg.Done()
			m.collectProject(ctx, callback, project)
		}(project)
	}

	wg.Wait()
}

func (m *MetricsCollectorDocker) collectProject(ctx context.Context, callback chan<- func(), project ConfigProjectDocker) {
	var err error
	var cveReport *CveResponse

	releaseMetrics := MetricCollectorList{}
	releaseCveMetrics := MetricCollectorList{}

	registryUrl, _, _ := project.GetRegistry()
	client := m.client[registryUrl]

	Logger.Infof("project[%v]: starting collection", project.Name)

	// init and fetch CVE
	if project.Cve.Vendor != "" && project.Cve.Product != "" {
		Logger.Infof("project[%v]: fetching cve report", project.Name)
		cveReport, err = m.cveClient.GetCveReport(project.Cve)

		if err != nil {
			Logger.Errorf("project[%v]: %v", project.Name, err)
		}
	}

	if imageTags, err := client.Tags(project.Image); err == nil {

		natsort.Sort(imageTags)

		for _, tag := range imageTags {
			if !project.IsReleaseValid(tag) {
				continue
			}

			releaseMetrics.AddInfo(prometheus.Labels{
				"name":   project.Name,
				"image":  project.Image,
				"tag":    tag,
				"marked": boolToString(project.IsReleaseMarked(tag)),
			})

			if manifest, err := client.Manifest(project.Image, tag); err == nil {
				var createdDate time.Time
				for _, h := range manifest.Manifest.History {
					var comp dockerManifestv1Compatibility

					if err := json.Unmarshal([]byte(h.V1Compatibility), &comp); err != nil {
						Logger.Errorf("project[%v]: %v", project.Name, err)
						continue
					}

					if createdDate.Before(comp.Created) {
						createdDate = comp.Created
					}
				}

				releaseMetrics.AddTime(prometheus.Labels{
					"name":   project.Name,
					"image":  project.Image,
					"tag":    tag,
					"marked": boolToString(project.IsReleaseMarked(tag)),
				}, createdDate)
			}

			if cveReport != nil {
				reportList := cveReport.GetReportByVersion(tag)

				for _, report := range reportList {
					releaseCveMetrics.Add(prometheus.Labels{
						"name":  project.Name,
						"image": project.Image,
						"tag":   tag,
						"cve":   report.Id,
					}, report.Cvss)
				}
			}
		}

	} else {
		Logger.Errorf("project[%v]: %v", project.Name, err)
	}

	// set metrics
	callback <- func() {
		releaseMetrics.GaugeSet(m.prometheus.release)
		releaseCveMetrics.GaugeSet(m.prometheus.releaseCve)
	}
}
