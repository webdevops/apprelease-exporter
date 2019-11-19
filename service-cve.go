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
		restClient *resty.Client
	}

	CveResponse struct {
		response *resty.Response

		conf ConfigProjectCommonCve

		report                 *CveResponseReport
		vulneratbilityVersions map[string][]CveResponseReportResultShort
	}

	CveResponseReport struct {
		Results []CveResponseReportResult `json:"results"`
	}

	CveResponseReportResultShort struct {
		Id   string
		Cvss float64
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

		Access struct {
			Authentication string
			Complexity     string
			Vector         string
		}

		Impact struct {
			Availability    string
			Confidentiality string
			Integrity       string
		}

		References []string
		Summary    string

		VulnerableConfiguration       []string `json:"vulnerable_configuration"`
		VulnerableConfigurationCpe2_2 []string `json:"vulnerable_configuration_cpe_2_2"`
		VulnerableProduct             []string `json:"vulnerable_product"`
	}
)

func NewCveClient() *CveClient {
	c := &CveClient{}
	c.restClient = resty.New()
	c.restClient.SetHeader("User-Agent", "apprelease-exporter/"+Version)
	c.restClient.SetHostURL("https://cve.circl.lu/")
	c.restClient.SetHeader("Accept", "application/json")

	return c
}

func (c *CveClient) GetCveReport(conf ConfigProjectCommonCve) (*CveResponse, error) {
	u := fmt.Sprintf(
		"/api/search/%v/%v",
		url.PathEscape(conf.Product),
		url.PathEscape(conf.Vendor),
	)
	resp, err := c.restClient.R().Get(u)
	if err != nil {
		return nil, err
	}

	r := &CveResponse{
		conf: conf,
	}
	if err := r.parseResponse(resp); err != nil {
		return nil, err
	}

	return r, nil
}

func (c *CveResponse) parseResponse(resp *resty.Response) error {
	confVendor := strings.ToLower(c.conf.Vendor)
	confProduct := strings.ToLower(c.conf.Product)

	c.report = &CveResponseReport{}
	c.vulneratbilityVersions = map[string][]CveResponseReportResultShort{}

	if err := json.Unmarshal(resp.Body(), &c.report); err != nil {
		return err
	}

	for _, report := range c.report.Results {
		for _, line := range report.VulnerableProduct {
			parsedLine := strings.Split(line, ":")

			if len(parsedLine) > 6 {
				lineVendor := strings.ToLower(parsedLine[3])
				lineProduct := strings.ToLower(parsedLine[4])
				lineVersion := strings.ToLower(parsedLine[5])

				if lineVendor == confVendor && lineProduct == confProduct {
					shortReport := CveResponseReportResultShort{
						Id:   report.Id,
						Cvss: report.Cvss,
					}

					c.vulneratbilityVersions[lineVersion] = append(
						c.vulneratbilityVersions[lineVersion],
						shortReport,
					)
				}
			}
		}
	}

	return nil
}

func (c *CveResponse) GetReportByVersion(version string) (ret []CveResponseReportResultShort) {
	ret = []CveResponseReportResultShort{}

	version = strings.ToLower(version)
	version = strings.TrimLeft(version, "v")

	fmt.Println(version)
	for key := range c.vulneratbilityVersions {
		fmt.Println(" -> " + key)
	}
	if val, ok := c.vulneratbilityVersions[version]; ok {
		ret = val
	}

	return ret
}
