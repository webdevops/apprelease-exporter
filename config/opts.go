package config

import (
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"
)

type (
	Opts struct {
		// logger
		Logger struct {
			Debug   bool `           long:"debug"        env:"DEBUG"    description:"debug mode"`
			Verbose bool `short:"v"  long:"verbose"      env:"VERBOSE"  description:"verbose mode"`
			LogJson bool `           long:"log.json"     env:"LOG_JSON" description:"Switch log output to json format"`
		}

		// config
		Config struct {
			Path string `long:"config" short:"c"  env:"CONFIG"   description:"Config path" required:"true"`
		}

		// scrape times
		Scrape struct {
			Time       time.Duration  `long:"scrape-time"         env:"SCRAPE_TIME"           description:"Default scrape time (time.duration)"       default:"12h"`
			TimeDocker *time.Duration `long:"scrape-time.docker"  env:"SCRAPE_TIME_DOCKER"    description:"Scrape time for Docker (time.duration)"`
			TimeGithub *time.Duration `long:"scrape-time.github"  env:"SCRAPE_TIME_GITHUB"    description:"Scrape time for Github (time.duration)"`
		}

		// CVE settings
		Cve struct {
			Url string `long:"cve.url"  env:"CVE_URL"    description:"URL to cve-search instance (see https://github.com/cve-search/cve-search)"`
		}

		// github
		GitHub struct {
			PersonalAccessToken *string       `long:"github.personalaccesstoken"  env:"GITHUB_PERSONALACCESSTOKEN" description:"GitHub personal access token" json:"-"`
			ScrapeWait          time.Duration `long:"github.scrape-wait"  env:"GITHUB_SCRAPEWAIT" description:"Wait number between project waits" default:"2s"`
			Limit               int           `long:"github.limit"  env:"GITHUB_LIMIT" description:"Number of results fetched from GitHub" default:"25"`
		}

		// docker
		Docker struct {
			Limit int `long:"docker.limit"  env:"DOCKER_LIMIT" description:"Number of tags fetched from Docker" default:"25"`
		}

		// cache
		Cache struct {
			Path string        `long:"cache.path"  env:"CACHE_PATH"  description:"Cache path"`
			Ttl  time.Duration `long:"cache.ttl"   env:"CACHE_TTL"   description:"Cache expiry" default:"24h"`
		}

		// general options
		ServerBind string `long:"bind"     env:"SERVER_BIND"   description:"Server address"     default:":8080"`
	}
)

func (o *Opts) GetJson() []byte {
	jsonBytes, err := json.Marshal(o)
	if err != nil {
		log.Panic(err)
	}
	return jsonBytes
}
