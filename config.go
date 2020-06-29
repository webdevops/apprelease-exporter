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
		Mark   []string                  `yaml:"mark"`

		Cve ConfigProjectCommonCve `yaml:"cve"`
	}

	ConfigProjectCommonCve struct {
		Vendor  string
		Product string
	}

	ConfigProjectCommonFilter struct {
		Whitelist       string
		whitelistRegexp *regexp.Regexp
		Blacklist       string
		blacklistRegexp *regexp.Regexp

		Replacement []ConfigProjectCommonReplacement `yaml:"replacement"`
	}

	ConfigProjectCommonReplacement struct {
		Match       string
		matchRegexp *regexp.Regexp
		Replace     string
	}

	ConfigProjectDocker struct {
		ConfigProjectCommon `yaml:",inline"`

		Image    string
		Registry ConfigProjectDockerRegistry `yaml:"registry"`
		Limit    *int                        `yaml:"limit"`
	}

	ConfigProjectDockerRegistry struct {
		Url      *string
		Username string
		Password string
	}

	ConfigProjectGithub struct {
		ConfigProjectCommon `yaml:",inline"`

		Project   string  `yaml:"project"`
		FetchType *string `yaml:"fetchType"`
		Limit     *int    `yaml:"limit"`
	}
)

func (p *ConfigProjectCommon) ProcessAndValidateVersion(val string) (version string, valid bool) {
	version = val
	valid = true

	// replacements
	for _, replacement := range p.Filter.Replacement {
		version = replacement.Apply(version)
	}

	// whitelist
	if p.Filter.Whitelist != "" {
		// cached regexp compilation
		if p.Filter.whitelistRegexp == nil {
			p.Filter.whitelistRegexp = regexp.MustCompile(strings.TrimSpace(p.Filter.Whitelist))
		}

		valid = p.Filter.whitelistRegexp.MatchString(version)
	}

	// blacklist
	if p.Filter.Blacklist != "" {
		// cached regexp compilation
		if p.Filter.blacklistRegexp == nil {
			p.Filter.blacklistRegexp = regexp.MustCompile(strings.TrimSpace(p.Filter.Blacklist))
		}

		if p.Filter.blacklistRegexp.MatchString(version) {
			valid = false
		}
	}

	return
}

func (r *ConfigProjectCommonReplacement) Apply(val string) string {
	if r.matchRegexp == nil {
		r.matchRegexp = regexp.MustCompile(r.Match)
	}
	val = r.matchRegexp.ReplaceAllString(val, r.Replace)
	return val
}

func (p *ConfigProjectCommon) CveReportClient() (client *CveClient) {
	if opts.CveUrl != "" && p.Cve.Vendor != "" && p.Cve.Product != "" {
		client = NewCveClient(p.Cve)
	}

	return
}

func (p *ConfigProjectCommon) IsReleaseMarked(val string) (ret bool) {
	ret = false

	for _, mark := range p.Mark {
		if strings.ToLower(mark) == strings.ToLower(val) {
			ret = true
			break
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

func (p *ConfigProjectGithub) GetFetchType() string {
	fetchtype := "releases"

	if p.FetchType != nil {
		switch *p.FetchType {
		case "tag":
		case "tags":
			fetchtype = "tags"
		}
	}

	return fetchtype
}

func (p *ConfigProjectDocker) GetLimit() int {
	if p.Limit != nil {
		return *p.Limit
	} else {
		return opts.DockerLimit
	}
}

func (p *ConfigProjectGithub) GetLimit() int {
	if p.Limit != nil {
		return *p.Limit
	} else {
		return opts.GithubLimit
	}
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
