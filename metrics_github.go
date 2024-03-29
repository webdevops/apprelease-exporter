package main

import (
	"context"
	"time"

	"github.com/google/go-github/v28/github"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	prometheusCommon "github.com/webdevops/go-prometheus-common"
	"golang.org/x/oauth2"
)

type (
	MetricsCollectorGithub struct {
		CollectorProcessorGeneral

		client *github.Client

		prometheus struct {
			release    *prometheus.GaugeVec
			releaseCve *prometheus.GaugeVec
		}
	}
)

func (m *MetricsCollectorGithub) Setup(collector *CollectorGeneral) {
	m.CollectorReference = collector

	if opts.GitHub.PersonalAccessToken != nil {
		// use personal access token
		ctx := context.Background()
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: *opts.GitHub.PersonalAccessToken},
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

	m.prometheus.release = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "apprelease_project_github_release",
			Help: "AppRelease project github release information",
		},
		[]string{
			"name",
			"project",
			"tag",
			"version",
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
			"version",
			"cve",
			"cwe",
			"vector",
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

func (m *MetricsCollectorGithub) Reset() {
	m.prometheus.release.Reset()
	m.prometheus.releaseCve.Reset()
}

func (m *MetricsCollectorGithub) Collect(ctx context.Context, logger *log.Entry, callback chan<- func()) {
	for _, project := range AppConfig.Projects.Github {
		func(project ConfigProjectGithub) {
			contextLogger := logger.WithField("project", project.Name)
			m.collectProject(ctx, contextLogger, callback, project)
		}(project)

		time.Sleep(opts.GitHub.ScrapeWait)
	}
}

func (m *MetricsCollectorGithub) collectProject(ctx context.Context, logger *log.Entry, callback chan<- func(), project ConfigProjectGithub) {
	var err error
	var releaseList []AppreleaseVersion
	var cveReport *CveResponse

	releaseMetrics := prometheusCommon.NewMetricsList()
	releaseCveMetrics := prometheusCommon.NewMetricsList()

	logger.Infof("starting collection")

	// init and fetch CVE
	cveClient := project.CveReportClient()
	if cveClient != nil {
		logger.Infof("fetching cve report")
		cveReport, err = cveClient.FetchReport()

		if err != nil {
			logger.Errorf(err.Error())
		}
	}

	switch project.GetFetchType() {
	case "tags":
		logger.Infof("fetching github versions from tags")
		releaseList, err = m.fetchGithubVersionFromTags(ctx, logger, project)
	default:
		logger.Infof("fetching github versions from releases")
		releaseList, err = m.fetchGithubVersionFromReleases(ctx, logger, project)
	}

	if err == nil {
		logger.Infof("found %v releases", len(releaseList))

		for _, release := range releaseList {
			if opts.Logger.Verbose {
				logger.Infof("found version %v on date %v", release.Version, release.CreatedAt.String())
			}

			releaseMetrics.AddTime(prometheus.Labels{
				"name":    project.Name,
				"project": project.Project,
				"tag":     release.Tag,
				"version": release.Version,
				"marked":  boolToString(project.IsReleaseMarked(release.Version)),
			}, *release.CreatedAt)

			// add cve report
			if cveReport != nil {
				reportList := cveReport.GetReportByVersion(release.Version)

				if opts.Logger.Verbose {
					logger.Infof("found %v cve reports for version %v", len(reportList), release.Version)
				}

				for _, report := range reportList {
					releaseCveMetrics.Add(prometheus.Labels{
						"name":                  project.Name,
						"project":               project.Project,
						"version":               release.Version,
						"cve":                   report.Id,
						"cwe":                   report.Cwe,
						"vector":                report.CvssVector,
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
		logger.Errorf(err.Error())
	}

	logger.Infof("finished")

	// set metrics
	callback <- func() {
		releaseMetrics.GaugeSet(m.prometheus.release)
		releaseCveMetrics.GaugeSet(m.prometheus.releaseCve)
	}
}

func (m *MetricsCollectorGithub) fetchGithubVersionFromReleases(ctx context.Context, logger *log.Entry, project ConfigProjectGithub) (releaseList []AppreleaseVersion, err error) {
	releaseList = []AppreleaseVersion{}

	githubOwner, githubRepository := project.GetOwnerAndRepository()

	listOpts := &github.ListOptions{
		Page:    0,
		PerPage: project.GetLimit(),
	}
	if respReleases, _, respError := m.client.Repositories.ListReleases(ctx, githubOwner, githubRepository, listOpts); respError == nil {
		for _, release := range respReleases {
			version, valid := project.ProcessAndValidateVersion(release.GetTagName())
			if !valid {
				// skip invalid version
				continue
			}

			createdAt := release.GetCreatedAt().Time

			releaseList = append(releaseList, AppreleaseVersion{
				Tag:       release.GetTagName(),
				Version:   version,
				CreatedAt: &createdAt,
			})
		}
	} else {
		err = respError
	}

	return
}

func (m *MetricsCollectorGithub) fetchGithubVersionFromTags(ctx context.Context, logger *log.Entry, project ConfigProjectGithub) (releaseList []AppreleaseVersion, err error) {
	var commit *github.RepositoryCommit
	releaseList = []AppreleaseVersion{}
	githubOwner, githubRepository := project.GetOwnerAndRepository()

	listOpts := &github.ListOptions{
		Page:    0,
		PerPage: project.GetLimit(),
	}
	if respTags, _, respError := m.client.Repositories.ListTags(ctx, githubOwner, githubRepository, listOpts); respError == nil {
		for _, tag := range respTags {
			version, valid := project.ProcessAndValidateVersion(tag.GetName())
			if !valid {
				// skip invalid version
				continue
			}

			commit, _, err = m.client.Repositories.GetCommit(ctx, githubOwner, githubRepository, tag.GetCommit().GetSHA())
			if err != nil {
				return
			}

			if commit != nil {
				createdAt := commit.GetCommit().GetAuthor().GetDate()
				releaseList = append(releaseList, AppreleaseVersion{
					Tag:       tag.GetName(),
					Version:   version,
					CreatedAt: &createdAt,
				})
			}
		}
	} else {
		err = respError
	}

	return
}
