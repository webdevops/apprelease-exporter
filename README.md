AppRelease and CVE Exporter
===========================

[![license](https://img.shields.io/github/license/webdevops/apprelease-exporter.svg)](https://github.com/webdevops/apprelease-exporter/blob/master/LICENSE)
[![Docker](https://img.shields.io/badge/docker-webdevops%2Fapprelease--exporter-blue.svg?longCache=true&style=flat&logo=docker)](https://hub.docker.com/r/webdevops/apprelease-exporter/)
[![Docker Build Status](https://img.shields.io/docker/build/webdevops/apprelease-exporter.svg)](https://hub.docker.com/r/webdevops/apprelease-exporter/)

Prometheus exporter for Application releases supports Docker and GitHub and is able to fetch CVE reports via [https://cve.circl.lu/](https://cve.circl.lu/).

Configuration
-------------

Normally no configuration is needed but can be customized using environment variables.

| Environment variable              | DefaultValue                | Description                                                       |
|-----------------------------------|-----------------------------|-------------------------------------------------------------------|
| `CONFIG`                          | `empty`                     | Path to configuration yaml, eg. see `example.yaml`                |
| `SCRAPE_TIME`                     | `12h`                       | Default scrape time (time.Duration)                               |
| `SCRAPE_TIME_DOCKER`              | -> SCRAPE_TIME              | Scrape time for Docker releases                                   |
| `SCRAPE_TIME_GITHUB  `            | -> SCRAPE_TIME              | Scrape time for GitHub releases                                   |
| `SERVER_BIND`                     | `:8080`                     | IP/Port binding                                                   |
| `DISABLE_CVE`                     | `empty`                     | Disable CVE report fetching (even if configured)                  |
| `GITHUB_PERSONALACCESSTOKEN`      | `empty`                     | GitHub personal access token for avoiding rate limit              |
| `GITHUB_SCRAPEWAIT`               | `2s`                        | Wait time between release scrapings to releax api stress          |
| `GITHUB_LIMIT`                    | `25`                        | Number of releases to fetch (only first page is scraped)          |
| `DOCKER_LIMIT`                    | `25`                        | Number of releases to fetch (only first page is scraped)          |
| `CACHE_PATH`                      | `empty`                     | Path where CVE json files should be stored                        |
| `CACHE_TTL`                       | `24h`                       | TTL (time.Duration) when cached CVE reports should be fetched again |

Configuration file
------------------

see [example.yaml](example.yaml)

Metrics
-------

| Metric                                         | Collector         | Description                                                                           |
|------------------------------------------------|-------------------|---------------------------------------------------------------------------------------|
| `apprelease_project_docker_release`            | docker            | List of images with tags, value is created time from manifest                         |
| `apprelease_project_docker_release_cve`        | docker            | List of CVE reports (if configured) with CVSS as value                                |
| `apprelease_project_github_release`            | github            | List of GitHub repository releases, value is created time                             |
| `apprelease_project_github_release_cve`        | github            | List of CVE reports (if configured) with CVSS as value                                |

Example
--------

* [example/metrics.txt](example/metrics.txt) (without CVE metrics)
* [example/metrics-cve.txt](example/metrics-cve.txt) (with CVE metrics)
