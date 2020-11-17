AppRelease and CVE Exporter
===========================

[![license](https://img.shields.io/github/license/webdevops/apprelease-exporter.svg)](https://github.com/webdevops/apprelease-exporter/blob/master/LICENSE)
[![DockerHub](https://img.shields.io/badge/DockerHub-webdevops%2Fapprelease--exporter-blue)](https://hub.docker.com/r/webdevops/apprelease-exporter/)
[![Quay.io](https://img.shields.io/badge/Quay.io-webdevops%2Fapprelease--exporter-blue)](https://quay.io/repository/webdevops/apprelease-exporter)

Prometheus exporter for Application releases supports Docker and GitHub and is able to fetch CVE reports via [https://cve.circl.lu/](https://cve.circl.lu/).

Usage
-----

```
Usage:
  apprelease-exporter [OPTIONS]

Application Options:
  -v, --verbose                     Verbose mode [$VERBOSE]
  -c, --config=                     Config path [$CONFIG]
      --bind=                       Server address (default: :8080) [$SERVER_BIND]
      --scrape-time=                Default scrape time (time.duration) (default: 12h) [$SCRAPE_TIME]
      --scrape-time.docker=         Scrape time for Docker (time.duration) [$SCRAPE_TIME_DOCKER]
      --scrape-time.github=         Scrape time for Github (time.duration) [$SCRAPE_TIME_GITHUB]
      --cve.url=                    URL to cve-search instance (see https://github.com/cve-search/cve-search) [$CVE_URL]
      --github.personalaccesstoken= GitHub personal access token [$GITHUB_PERSONALACCESSTOKEN]
      --github.scrape-wait=         Wait number between project waits (default: 2s) [$GITHUB_SCRAPEWAIT]
      --github.limit=               Number of results fetched from GitHub (default: 25) [$GITHUB_LIMIT]
      --docker.limit=               Number of tags fetched from Docker (default: 25) [$DOCKER_LIMIT]
      --cache.path=                 Cache path [$CACHE_PATH]
      --cache.ttl=                  Cache expiry (default: 24h) [$CACHE_TTL]

Help Options:
  -h, --help                        Show this help message
```

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
