package main

import (
	"context"
	"golang.org/x/oauth2"
	"github.com/google/go-github/v28/github"
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

type (
	MetricsCollectorGithub struct {
		CollectorProcessorGeneral

		client *github.Client

		prometheus struct {
			release *prometheus.GaugeVec
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
	} else {
		// anonymous
		m.client = github.NewClient(nil)
	}

	m.prometheus.release = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apprelease_project_github_release",
			Help: "AppRelease project github release information",
		},
		[]string{
			"name",
			"project",
			"release",
		},
	)

	prometheus.MustRegister(m.prometheus.release)
}

func (m *MetricsCollectorGithub) Reset() {
	m.prometheus.release.Reset()
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
	releaseMetrics := MetricCollectorList{}

	githubOwner, githubRepository := project.GetOwnerAndRepository()

	Logger.Infof("project[%v]: starting collection", project.Name)

	listOpts := &github.ListOptions{
		Page:    0,
		PerPage: opts.GithubPerPage,
	}
	releaseList, _, err := m.client.Repositories.ListReleases(ctx, githubOwner, githubRepository, listOpts)
	if err == nil {

		for _, release := range releaseList {
			if !project.IsReleaseValid(release.GetTagName()) {
				continue
			}

			releaseMetrics.AddTime(prometheus.Labels{
				"name":    project.Name,
				"project": project.Project,
				"release": release.GetTagName(),
			}, release.GetCreatedAt().Time)
		}

	} else {
		Logger.Errorf("project[%v]: %v", project.Name, err)
	}

	// set metrics
	callback <- func() {
		releaseMetrics.GaugeSet(m.prometheus.release)
	}
}
