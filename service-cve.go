package main

import (
	"encoding/json"
	"fmt"
	resty "github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
)

type (
	CveClient struct {
		conf ConfigProjectCommonCve

		restClient *resty.Client
	}

	CveResponse struct {
		conf                   ConfigProjectCommonCve
		report                 *CveResponseReport
		vulneratbilityVersions map[string]map[string]CveResponseReportResultShort
	}

	CveResponseReport struct {
		Results []CveResponseReportResult `json:"results"`
	}

	CveResponseReportResultShort struct {
		Id         string                        `json:"id"`
		Cvss       float64                       `json:"cvss"`
		CvssVector string                        `json:"cvss-vector"`
		Cwe        string                        `json:"cwe"`
		Access     CveResponseReportResultAccess `json:"access"`
		Impact     CveResponseReportResultImpact `json:"impact"`
	}

	CveResponseReportResult struct {
		Id string `json:"id"`

		Modified  string `json:"modified"`
		Published string `json:"published"`

		Assigner   string  `json:"assigner"`
		Cvss       float64 `json:"cvss"`
		CvssTime   string  `json:"cvss-time"`
		CvssVector string  `json:"cvss-vector"`
		Cwe        string  `json:"cwe"`

		Access CveResponseReportResultAccess `json:"access"`
		Impact CveResponseReportResultImpact `json:"impact"`

		References []string `json:"references"`
		Summary    string   `json:"summary"`

		VulnerableConfiguration       []string `json:"vulnerable_configuration"`
		VulnerableConfigurationCpe2_2 []string `json:"vulnerable_configuration_cpe_2_2"`
		VulnerableProduct             []string `json:"vulnerable_product"`
	}

	CveResponseReportResultAccess struct {
		Authentication string `json:"authentication"`
		Complexity     string `json:"complexity"`
		Vector         string `json:"vector"`
	}

	CveResponseReportResultImpact struct {
		Availability    string `json:"Availability"`
		Confidentiality string `json:"confidentiality"`
		Integrity       string `json:"integrity"`
	}
)

func NewCveClient(conf ConfigProjectCommonCve) *CveClient {
	c := &CveClient{}

	c.conf = conf

	c.restClient = resty.New()
	c.restClient.SetHeader("User-Agent", fmt.Sprintf("apprelease-exporter/%s", gitTag))
	c.restClient.SetHostURL(opts.Cve.Url)
	c.restClient.SetHeader("Accept", "application/json")

	return c
}

func (c *CveClient) FetchReport() (*CveResponse, error) {
	// fetch from cache (if active, use ttl)
	if r, useFromCache := c.loadFromCache(false); useFromCache {
		return r, nil
	}

	// fetch from api
	if r, err := c.fetchFromApi(); err == nil {
		c.saveToCache(r)
		return r, nil
	} else {
		log.Errorf("unable to fetch cve %v/%v: %v", c.conf.Vendor, c.conf.Product, err)
	}

	// fallback (if active, ignore ttl)
	if r, useFromCache := c.loadFromCache(true); useFromCache {
		return r, nil
	}

	// no cve report available
	return nil, nil
}

func (c *CveClient) fetchFromApi() (*CveResponse, error) {
	log.Debugf("fetch cve %v/%v from online api", c.conf.Vendor, c.conf.Product)

	u := fmt.Sprintf(
		"/api/search/%v/%v",
		url.PathEscape(c.conf.Vendor),
		url.PathEscape(c.conf.Product),
	)
	resp, err := c.restClient.R().Get(u)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 {
		err = fmt.Errorf("fetch cve %v/%v from online api, got HTTP status %v: %v", c.conf.Vendor, c.conf.Product, resp.StatusCode(), resp.Request.URL)
		return nil, err
	}

	data := resp.Body()

	r := &CveResponse{
		conf: c.conf,
	}

	if err := r.parseResponse(data); err != nil {
		return nil, err
	}

	return r, nil
}

func (c *CveResponse) parseResponse(data []byte) error {
	c.report = &CveResponseReport{}
	c.vulneratbilityVersions = map[string]map[string]CveResponseReportResultShort{}

	if err := json.Unmarshal(data, &c.report); err != nil {
		return err
	}

	for _, report := range c.report.Results {
		c.parseReportLine(report, report.VulnerableProduct)
		c.parseReportLine(report, report.VulnerableConfiguration)
		c.parseReportLine(report, report.VulnerableConfigurationCpe2_2)
	}

	return nil
}

func (c *CveClient) buildCacheFilePath() (filepath string) {
	vendor := strings.ToLower(c.conf.Vendor)
	product := strings.ToLower(c.conf.Product)

	filepath = path.Join(opts.Cache.Path, fmt.Sprintf("cve-%v_%v.json", vendor, product))

	return
}

func (c *CveClient) loadFromCache(force bool) (*CveResponse, bool) {
	if opts.Cache.Path != "" {
		cvePath := c.buildCacheFilePath()

		if stat, err := os.Stat(cvePath); err == nil {
			if force || time.Now().Before(stat.ModTime().Add(opts.Cache.Ttl)) {
				log.Debugf("read cve from cached file %v", cvePath)

				content, err := ioutil.ReadFile(cvePath)
				if err != nil {
					log.Errorf("unable to read cve cache file %v", cvePath)
					return nil, false
				}

				r := &CveResponse{
					conf: c.conf,
				}

				if err := r.parseResponse(content); err != nil {
					return nil, false
				}

				return r, true
			} else {
				log.Debugf("found expired cve cache file %v", cvePath)
			}
		}
	}

	return nil, false
}

func (c *CveClient) saveToCache(r *CveResponse) {
	if opts.Cache.Path != "" {
		cvePath := c.buildCacheFilePath()

		log.Debugf("write cve to cache file %v", cvePath)

		if data, err := json.Marshal(&r.report); err == nil {
			if err := ioutil.WriteFile(cvePath, data, 0644); err != nil {
				log.Errorf("unable to write cve cache file %v", cvePath)
			}
		} else {
			log.Errorf("unable to marshal cve report to json")
		}
	}
}

func (c *CveResponse) parseReportLine(report CveResponseReportResult, reportLines []string) {
	vendor := strings.ToLower(c.conf.Vendor)
	product := strings.ToLower(c.conf.Product)

	for _, line := range reportLines {
		parsedLine := strings.Split(line, ":")

		if len(parsedLine) >= 6 {
			lineVendor := strings.ToLower(parsedLine[3])
			lineProduct := strings.ToLower(parsedLine[4])
			lineVersion := strings.ToLower(parsedLine[5])
			lineVersionType := strings.ToLower(parsedLine[6])

			if lineVersionType != "" && lineVersionType != "*" && lineVersionType != "-" {
				// beta, rc version or whatever
				continue
			}

			if lineVendor == vendor && lineProduct == product {
				shortReport := CveResponseReportResultShort{
					Id:         report.Id,
					Cvss:       report.Cvss,
					Cwe:        report.Cwe,
					CvssVector: report.CvssVector,
					Access:     report.Access,
					Impact:     report.Impact,
				}

				if _, ok := c.vulneratbilityVersions[lineVersion]; !ok {
					c.vulneratbilityVersions[lineVersion] = map[string]CveResponseReportResultShort{}
				}

				c.vulneratbilityVersions[lineVersion][report.Id] = shortReport
			}
		}
	}
}

func (c *CveResponse) GetReportByVersion(version string) (ret []CveResponseReportResultShort) {
	ret = []CveResponseReportResultShort{}

	version = strings.ToLower(version)
	if reports, ok := c.vulneratbilityVersions[version]; ok {
		for _, report := range reports {
			ret = append(ret, report)
		}
	}

	return ret
}
