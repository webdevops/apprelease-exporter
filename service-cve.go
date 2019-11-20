package main

import (
	"encoding/json"
	"fmt"
	resty "github.com/go-resty/resty/v2"
	"net/url"
	"strings"
)

type (
	CveClient struct {
		conf ConfigProjectCommonCve

		restClient *resty.Client
	}

	CveResponse struct {
		response               *resty.Response
		conf                   ConfigProjectCommonCve
		report                 *CveResponseReport
		vulneratbilityVersions map[string]map[string]CveResponseReportResultShort
	}

	CveResponseReport struct {
		Results []CveResponseReportResult `json:"results"`
	}

	CveResponseReportResultShort struct {
		Id     string
		Cvss   float64
		Access CveResponseReportResultAccess
		Impact CveResponseReportResultImpact
	}

	CveResponseReportResult struct {
		Id string

		Modified  string
		Published string

		Assigner   string
		Cvss       float64
		CvssTime   string `json:"cvss-time"`
		CvssVector string `json:"cvss-vector"`
		Cwe        string

		Access CveResponseReportResultAccess
		Impact CveResponseReportResultImpact

		References []string
		Summary    string

		VulnerableConfiguration       []string `json:"vulnerable_configuration"`
		VulnerableConfigurationCpe2_2 []string `json:"vulnerable_configuration_cpe_2_2"`
		VulnerableProduct             []string `json:"vulnerable_product"`
	}

	CveResponseReportResultAccess struct {
		Authentication string
		Complexity     string
		Vector         string
	}

	CveResponseReportResultImpact struct {
		Availability    string
		Confidentiality string
		Integrity       string
	}
)

func NewCveClient(conf ConfigProjectCommonCve) *CveClient {
	c := &CveClient{}

	c.conf = conf

	c.restClient = resty.New()
	c.restClient.SetHeader("User-Agent", "apprelease-exporter/"+Version)
	c.restClient.SetHostURL("https://cve.circl.lu/")
	c.restClient.SetHeader("Accept", "application/json")

	return c
}

func (c *CveClient) FetchReport() (*CveResponse, error) {
	u := fmt.Sprintf(
		"/api/search/%v/%v",
		url.PathEscape(c.conf.Vendor),
		url.PathEscape(c.conf.Product),
	)
	resp, err := c.restClient.R().Get(u)
	if err != nil {
		return nil, err
	}

	r := &CveResponse{
		conf: c.conf,
	}
	if err := r.parseResponse(resp); err != nil {
		return nil, err
	}

	return r, nil
}

func (c *CveResponse) parseResponse(resp *resty.Response) error {
	c.report = &CveResponseReport{}
	c.vulneratbilityVersions = map[string]map[string]CveResponseReportResultShort{}

	if err := json.Unmarshal(resp.Body(), &c.report); err != nil {
		return err
	}

	for _, report := range c.report.Results {
		c.parseReportLine(report, report.VulnerableProduct)
		c.parseReportLine(report, report.VulnerableConfiguration)
		c.parseReportLine(report, report.VulnerableConfigurationCpe2_2)
	}

	// cleanup
	c.report = nil

	return nil
}

func (c *CveResponse) parseReportLine(report CveResponseReportResult, reportLines []string) {
	vendor := strings.ToLower(c.conf.Vendor)
	product := strings.ToLower(c.conf.Product)

	for _, line := range reportLines {
		parsedLine := strings.Split(line, ":")

		if len(parsedLine) >= 5 {
			lineVendor := strings.ToLower(parsedLine[3])
			lineProduct := strings.ToLower(parsedLine[4])
			lineVersion := strings.ToLower(parsedLine[5])

			if lineVendor == vendor && lineProduct == product {
				shortReport := CveResponseReportResultShort{
					Id:     report.Id,
					Cvss:   report.Cvss,
					Access: report.Access,
					Impact: report.Impact,
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
