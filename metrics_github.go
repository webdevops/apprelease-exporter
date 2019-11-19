package main

import (
	"context"
	"github.com/google/go-github/v28/github"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/oauth2"
	"time"
)

type (
	MetricsCollectorGithub struct {
		CollectorProcessorGeneral

		client    *github.Client
		cveClient *CveClient

		prometheus struct {
			release    *prometheus.GaugeVec
			releaseCve *prometheus.GaugeVec
		}
	}
)

func (m *MetricsCollectorGithub) Setup(collector *CollectorGeneral) {
	m.CollectorReference = collector

	if opts.GithubPersonalAccessToken != nil {
		// use personal access token
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: *opts.GithubPersonalAccessToken},
		)
		tc := oauth2.NewClient(ctx, ts)
		m.client = github.NewClient(tc)

		// ping github api to check credentials
		req, err := m.client.NewRequest("GET", "/", nil)
		if err != nil {
			panic(err)
		}
		_, err = m.client.Do(ctx, req, nil)
		if err != nil {
			panic(err)
		}
	} else {
		// anonymous
		m.client = github.NewClient(nil)
	}

	m.cveClient = NewCveClient()

	m.prometheus.release = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apprelease_project_github_release",
			Help: "AppRelease project github release information",
		},
		[]string{
			"name",
			"project",
			"release",
			"marked",
		},
	)

	m.prometheus.releaseCve = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apprelease_project_github_release_cve",
			Help: "AppRelease project github release cve reports",
		},
		[]string{
			"name",
			"project",
			"release",
			"cve",
		},
	)

	prometheus.MustRegister(m.prometheus.release)
	prometheus.MustRegister(m.prometheus.releaseCve)
}

func (m *MetricsCollectorGithub) Reset() {
	m.prometheus.release.Reset()
	m.prometheus.releaseCve.Reset()
}

func (m *MetricsCollectorGithub) Collect(ctx context.Context, callback chan<- func()) {
	for _, project := range AppConfig.Projects.Github {
		func(project ConfigProjectGithub) {
			m.collectProject(ctx, callback, project)
		}(project)

		time.Sleep(opts.GithubScrapeWait)
	}
}

func (m *MetricsCollectorGithub) collectProject(ctx context.Context, callback chan<- func(), project ConfigProjectGithub) {
	var err error
	var cveReport *CveResponse

	releaseMetrics := MetricCollectorList{}
	releaseCveMetrics := MetricCollectorList{}

	githubOwner, githubRepository := project.GetOwnerAndRepository()
	Logger.Infof("project[%v]: starting collection", project.Name)

	// init and fetch CVE
	if project.Cve.Vendor != "" && project.Cve.Product != "" {
		Logger.Infof("project[%v]: fetching cve report", project.Name)
		cveReport, err = m.cveClient.GetCveReport(project.Cve)

		if err != nil {
			Logger.Errorf("project[%v]: %v", project.Name, err)
		}
	}

	listOpts := &github.ListOptions{
		Page:    0,
		PerPage: opts.GithubPerPage,
	}
	releaseList, _, err := m.client.Repositories.ListReleases(ctx, githubOwner, githubRepository, listOpts)
	if err == nil {

		for _, release := range releaseList {
			releaseVersion := release.GetTagName()

			if !project.IsReleaseValid(releaseVersion) {
				continue
			}

			releaseMetrics.AddTime(prometheus.Labels{
				"name":    project.Name,
				"project": project.Project,
				"release": releaseVersion,
				"marked":  boolToString(project.IsReleaseMarked(releaseVersion)),
			}, release.GetCreatedAt().Time)

			if cveReport != nil {
				reportList := cveReport.GetReportByVersion(releaseVersion)

				for _, report := range reportList {
					releaseCveMetrics.Add(prometheus.Labels{
						"name":    project.Name,
						"project": project.Project,
						"release": releaseVersion,
						"cve":     report.Id,
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
