package main

import (
	"context"
	"encoding/json"
	"facette.io/natsort"
	"fmt"
	"github.com/heroku/docker-registry-client/registry"
	"github.com/prometheus/client_golang/prometheus"
	"math"
	"sort"
	"sync"
	"time"
)

type (
	MetricsCollectorDocker struct {
		CollectorProcessorGeneral

		client map[string]*registry.Registry

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

	m.prometheus.release = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apprelease_project_docker_release",
			Help: "AppRelease project docker information",
		},
		[]string{
			"name",
			"image",
			"tag",
			"version",
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
			"version",
			"cve",
			"accessAuthentication",
			"accessComplexity",
			"accessVector",
			"impactAvailability",
			"impactConfidentiality",
			"impactIntegrity",
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
	cveClient := project.CveReportClient()
	if cveClient != nil {
		Logger.Infof("project[%v]: fetching cve report", project.Name)
		cveReport, err = cveClient.FetchReport()

		if err != nil {
			Logger.Errorf("project[%v]: %v", project.Name, err)
		}
	}

	releaseList, err := m.fetchDockerTags(ctx, project, client)

	if err == nil {
		for _, release := range releaseList {
			if release.CreatedAt != nil {
				Logger.Verbosef("project[%v]: found version %v on date %v", project.Name, release.Version, release.CreatedAt.String())
				releaseMetrics.AddTime(prometheus.Labels{
					"name":    project.Name,
					"image":   project.Image,
					"tag":     release.Tag,
					"version": release.Version,
					"marked":  boolToString(project.IsReleaseMarked(release.Version)),
				}, *release.CreatedAt)

			} else {
				Logger.Verbosef("project[%v]: found version %v without date", project.Name, release.Version)

				releaseMetrics.AddInfo(prometheus.Labels{
					"name":    project.Name,
					"image":   project.Image,
					"tag":     release.Tag,
					"version": release.Version,
					"marked":  boolToString(project.IsReleaseMarked(release.Version)),
				})
			}

			// add cve report
			if cveReport != nil {
				reportList := cveReport.GetReportByVersion(release.Version)

				Logger.Verbosef("project[%v]: found %v cve reports for version %v", project.Name, len(reportList), release.Version)

				for _, report := range reportList {
					releaseCveMetrics.Add(prometheus.Labels{
						"name":                  project.Name,
						"image":                 project.Image,
						"version":               release.Version,
						"cve":                   report.Id,
						"accessAuthentication":  report.Access.Authentication,
						"accessComplexity":      report.Access.Complexity,
						"accessVector":          report.Access.Vector,
						"impactAvailability":    report.Impact.Availability,
						"impactConfidentiality": report.Impact.Confidentiality,
						"impactIntegrity":       report.Impact.Integrity,
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

func (m *MetricsCollectorDocker) fetchDockerTags(ctx context.Context, project ConfigProjectDocker, client *registry.Registry) (releaseList []AppreleaseVersion, err error) {
	var createdAt *time.Time
	releaseList = []AppreleaseVersion{}

	if rawImageTags, err := client.Tags(project.Image); err == nil {
		// remove all invalid versions
		imageTags := []string{}
		for _, rawTag := range rawImageTags {
			_, valid := project.ProcessAndValidateVersion(rawTag)
			if !valid {
				// skip invalid version
				continue
			}

			imageTags = append(imageTags, rawTag)
		}

		// natural sort and reverse, get latest versions
		natsort.Sort(imageTags)
		sort.Sort(sort.Reverse(sort.StringSlice(imageTags)))

		// apply limit
		sliceLimit := int(math.Min(float64(len(imageTags)), float64(project.GetLimit())))
		imageTags = imageTags[:sliceLimit]

		for _, tag := range imageTags {
			createdAt = nil

			version, valid := project.ProcessAndValidateVersion(tag)
			if !valid {
				// skip invalid version
				continue
			}

			if manifest, err := client.Manifest(project.Image, tag); err == nil {
				for _, h := range manifest.Manifest.History {
					var comp dockerManifestv1Compatibility

					if err := json.Unmarshal([]byte(h.V1Compatibility), &comp); err != nil {
						Logger.Errorf("project[%v]: %v", project.Name, err)
						continue
					}

					if createdAt == nil || createdAt.Before(comp.Created) {
						createdAt = &comp.Created
					}
				}
			}

			releaseList = append(releaseList, AppreleaseVersion{
				Tag:       tag,
				Version:   version,
				CreatedAt: createdAt,
			})
		}
	}

	return
}
