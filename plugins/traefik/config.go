package traefik

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type DynamicConfiguration struct {
	DisplayName      string `yaml:"displayname"`
	ShowDetails      *bool  `yaml:"showDetails"`
	Theme            string `yaml:"theme"`
	RefreshFrequency string `yaml:"refreshFrequency"`
}

type BlockingConfiguration struct {
	Timeout string `yaml:"timeout"`
}

type Config struct {
	SablierURL      string `yaml:"sablierUrl"`
	Names           string `yaml:"names"`
	Group           string `yaml:"group"`
	SessionDuration string `yaml:"sessionDuration"`
	SkipOnFail      bool   `yaml:"skipOnFail"`
	splittedNames   []string
	Dynamic         *DynamicConfiguration  `yaml:"dynamic"`
	Blocking        *BlockingConfiguration `yaml:"blocking"`
}

func CreateConfig() *Config {
	return &Config{
		SablierURL:      "http://sablier:10000",
		Names:           "",
		Group:           "",
		SessionDuration: "",
		SkipOnFail:      false,
		splittedNames:   []string{},
		Dynamic:         nil,
		Blocking:        nil,
	}
}

func (c *Config) BuildRequest(middlewareName string) (*http.Request, error) {

	if len(c.SablierURL) == 0 {
		return nil, fmt.Errorf("sablierURL cannot be empty")
	}

	names := strings.Split(c.Names, ",")
	for i := range names {
		names[i] = strings.TrimSpace(names[i])
	}

	if len(names) >= 1 && len(names[0]) > 0 {
		c.splittedNames = names
	}

	if len(names) == 0 && len(c.Group) == 0 {
		return nil, fmt.Errorf("you must specify at least one name or a group")
	}

	if c.Dynamic != nil && c.Blocking != nil {
		return nil, fmt.Errorf("only supply one strategy: dynamic or blocking")
	}

	if c.Dynamic != nil {
		return c.buildDynamicRequest(middlewareName)
	} else if c.Blocking != nil {
		return c.buildBlockingRequest()
	}
	return nil, fmt.Errorf("no strategy configured")
}

func (c *Config) buildDynamicRequest(middlewareName string) (*http.Request, error) {
	if c.Dynamic == nil {
		return nil, fmt.Errorf("dynamic config is nil")
	}

	request, err := http.NewRequest("GET", fmt.Sprintf("%s/api/strategies/dynamic", c.SablierURL), nil)
	if err != nil {
		return nil, err
	}

	q := request.URL.Query()

	if c.SessionDuration != "" {
		_, err = time.ParseDuration(c.SessionDuration)

		if err != nil {
			return nil, fmt.Errorf("error parsing dynamic.sessionDuration: %v", err)
		}

		q.Add("session_duration", c.SessionDuration)
	}

	for _, name := range c.splittedNames {
		q.Add("names", name)
	}

	if c.Group != "" {
		q.Add("group", c.Group)
	}

	if c.Dynamic.DisplayName != "" {
		q.Add("display_name", c.Dynamic.DisplayName)
	} else {
		// display name defaults as middleware name
		q.Add("display_name", middlewareName)
	}

	if c.Dynamic.Theme != "" {
		q.Add("theme", c.Dynamic.Theme)
	}

	if c.Dynamic.RefreshFrequency != "" {
		_, err := time.ParseDuration(c.Dynamic.RefreshFrequency)

		if err != nil {
			return nil, fmt.Errorf("error parsing dynamic.refreshFrequency: %v", err)
		}

		q.Add("refresh_frequency", c.Dynamic.RefreshFrequency)
	}

	if c.Dynamic.ShowDetails != nil {
		q.Add("show_details", strconv.FormatBool(*c.Dynamic.ShowDetails))
	}

	request.URL.RawQuery = q.Encode()

	return request, nil
}

func (c *Config) buildBlockingRequest() (*http.Request, error) {
	if c.Blocking == nil {
		return nil, fmt.Errorf("blocking config is nil")
	}

	request, err := http.NewRequest("GET", fmt.Sprintf("%s/api/strategies/blocking", c.SablierURL), nil)
	if err != nil {
		return nil, err
	}

	q := request.URL.Query()

	if c.SessionDuration != "" {
		_, err = time.ParseDuration(c.SessionDuration)

		if err != nil {
			return nil, fmt.Errorf("error parsing dynamic.sessionDuration: %v", err)
		}

		q.Add("session_duration", c.SessionDuration)
	}

	for _, name := range c.splittedNames {
		q.Add("names", name)
	}

	if c.Group != "" {
		q.Add("group", c.Group)
	}

	if c.Blocking.Timeout != "" {
		_, err := time.ParseDuration(c.Blocking.Timeout)

		if err != nil {
			return nil, fmt.Errorf("error paring blocking.timeout: %v", err)
		}

		q.Add("timeout", c.Blocking.Timeout)
	}

	request.URL.RawQuery = q.Encode()

	return request, nil
}
