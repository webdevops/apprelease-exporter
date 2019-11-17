package main

import (
	"bytes"
	"github.com/Masterminds/sprig"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"regexp"
	"strings"
	"text/template"
)

type (
	Config struct {
		Projects ConfigProjects `yaml:"projects"`
	}

	ConfigProjects struct {
		Docker []ConfigProjectDocker `yaml:"docker"`
		Github []ConfigProjectGithub `yaml:"github"`
	}

	ConfigProjectCommon struct {
		Name   string                    `yaml:"name"`
		Filter ConfigProjectCommonFilter `yaml:"filter"`
	}

	ConfigProjectCommonFilter struct {
		Whitelist       string
		whitelistRegexp *regexp.Regexp
		Blacklist       string
		blacklistRegexp *regexp.Regexp
	}

	ConfigProjectDocker struct {
		ConfigProjectCommon `yaml:",inline"`

		Image    string
		Registry ConfigProjectDockerRegistry `yaml:"registry"`
	}

	ConfigProjectDockerRegistry struct {
		Url      *string
		Username string
		Password string
	}

	ConfigProjectGithub struct {
		ConfigProjectCommon `yaml:",inline"`

		Project string `yaml:"project"`
	}
)

func (p *ConfigProjectCommon) IsReleaseValid(val string) (ret bool) {
	ret = true

	// whitelist
	if p.Filter.Whitelist != "" {
		// cached regexp compilation
		if p.Filter.whitelistRegexp == nil {
			p.Filter.whitelistRegexp = regexp.MustCompile(strings.TrimSpace(p.Filter.Whitelist))
		}

		ret = p.Filter.whitelistRegexp.MatchString(val)
	}

	// blacklist
	if p.Filter.Blacklist != "" {
		// cached regexp compilation
		if p.Filter.blacklistRegexp == nil {
			p.Filter.blacklistRegexp = regexp.MustCompile(strings.TrimSpace(p.Filter.Blacklist))
		}

		if p.Filter.blacklistRegexp.MatchString(val) {
			ret = false
		}
	}

	return
}

func (p *ConfigProjectDocker) GetRegistry() (url, username, password string) {
	if p.Registry.Url != nil {
		url = *p.Registry.Url
		username = p.Registry.Username
		password = p.Registry.Password
	} else {
		url = "https://registry-1.docker.io/"
		username = ""
		password = ""
	}

	return
}

func (p *ConfigProjectGithub) GetOwnerAndRepository() (owner, repository string) {
	parts := strings.SplitN(p.Project, "/", 2)
	owner = parts[0]
	repository = parts[1]

	return
}

func NewAppConfig(path string) (config Config) {
	var configRaw []byte

	config = Config{}

	Logger.Infof("reading configuration from file %v", path)
	if data, err := ioutil.ReadFile(path); err == nil {
		configRaw = data
	} else {
		panic(err)
	}

	Logger.Info(" -  preprocessing with template engine")
	var tmplBytes bytes.Buffer
	parsedConfig, err := template.New("yaml").Funcs(sprig.TxtFuncMap()).Parse(string(configRaw))
	if err != nil {
		panic(err)
	}

	if err := parsedConfig.Execute(&tmplBytes, nil); err != nil {
		panic(err)
	}

	Logger.Info("parsing configuration")
	if err := yaml.Unmarshal(tmplBytes.Bytes(), &config); err != nil {
		panic(err)
	}

	return
}
