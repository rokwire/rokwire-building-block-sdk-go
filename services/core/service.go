// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/rokwireutils"
)

// Service contains configurations and helper functions required to utilize certain core services
type Service struct {
	serviceAccountManager *auth.ServiceAccountManager

	deletedAccountsConfig *DeletedAccountsConfig

	logger *logs.Logger
}

// StartDeletedAccountsTimer starts a timer that periodically retrieves deleted account IDs
func (c *Service) StartDeletedAccountsTimer() {
	//cancel if active
	if c.deletedAccountsConfig.timer != nil {
		c.deletedAccountsConfig.timerDone <- true
		c.deletedAccountsConfig.timer.Stop()
	}

	c.getDeletedAccountsWithCallback(c.deletedAccountsConfig.Callback)
}

func (c *Service) getDeletedAccountsWithCallback(callback func([]string) error) {
	accountIDs, err := c.getDeletedAccounts()
	if err != nil && c.logger != nil {
		c.logger.Error(err.Error())
	}

	err = callback(accountIDs)
	if err != nil && c.logger != nil {
		c.logger.Errorf("received error from callback function: %v", err)
	}

	duration := time.Hour * time.Duration(int64(c.deletedAccountsConfig.Period))
	c.deletedAccountsConfig.timer = time.NewTimer(duration)
	select {
	case <-c.deletedAccountsConfig.timer.C:
		// timer expired
		c.deletedAccountsConfig.timer = nil

		c.getDeletedAccountsWithCallback(callback)
	case <-c.deletedAccountsConfig.timerDone:
		// timer aborted
		c.deletedAccountsConfig.timer = nil
	}
}

func (c *Service) getDeletedAccounts() ([]string, error) {
	accountIDs := make([]string, 0)

	req, err := c.buildDeletedAccountsRequest()
	if err != nil {
		return nil, fmt.Errorf("error building deleted accounts request: %v", err)
	}

	responses := c.serviceAccountManager.MakeRequests(req, nil)
	for _, reqResp := range responses {
		if reqResp.Error != nil && c.logger != nil {
			c.logger.Errorf("error making deleted accounts request: %v", reqResp.Error)
			continue
		}

		body, err := rokwireutils.ReadResponseBody(reqResp.Response)
		if err != nil {
			return nil, fmt.Errorf("error reading deleted accounts response body: %v", err)
		}

		var deleted []string
		err = json.Unmarshal(body, &deleted)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling deleted accounts response body: %v", err)
		}

		accountIDs = append(accountIDs, deleted...)
	}

	return accountIDs, nil
}

func (c *Service) buildDeletedAccountsRequest() (*http.Request, error) {
	req, err := http.NewRequest("GET", c.serviceAccountManager.AuthService.AuthBaseURL+c.deletedAccountsConfig.path, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to get deleted accounts: %v", err)
	}

	return req, nil
}

// GetUserAccounts Gets user accounts
func (c *Service) GetUserAccounts(searchParams map[string]interface{}, appID *string, orgID *string, limit *int, offset *int) ([]AccountResponse, error) {
	if c.serviceAccountManager == nil {
		log.Println("GetAccounts: service account manager is nil")
		return nil, errors.New("service account manager is nil")
	}

	url := fmt.Sprintf("%s/bbs/accounts", c.serviceAccountManager.AuthService.AuthBaseURL)

	bodyBytes, err := json.Marshal(searchParams)
	if err != nil {
		log.Printf("GetAccounts: error marshalling body - %s", err)
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("GetAccounts: error creating request - %s", err)
		return nil, err
	}

	params := req.URL.Query()
	if appID != nil {
		params.Add("app_id", *appID)
	}
	if orgID != nil {
		params.Add("org_id", *orgID)
	}
	if limit != nil {
		params.Add("limit", fmt.Sprintf("%d", *limit))
	}
	if offset != nil {
		params.Add("offset", fmt.Sprintf("%d", *offset))
	}
	req.URL.RawQuery = params.Encode()

	req.Header.Add("Content-Type", "application/json")

	appIDVal := "all"
	if appID != nil {
		appIDVal = *appID
	}
	orgIDVal := "all"
	if orgID != nil {
		appIDVal = *orgID
	}
	resp, err := c.serviceAccountManager.MakeRequest(req, appIDVal, orgIDVal)
	if err != nil {
		log.Printf("GetAccounts: error sending request - %s", err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("GetAccounts: error with response code - %d", resp.StatusCode)
		return nil, fmt.Errorf("GetAccounts: error with response code != 200")
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("GetAccounts: unable to read json: %s", err)
		return nil, fmt.Errorf("GetAccounts: unable to parse json: %s", err)
	}

	var maping []Account
	err = json.Unmarshal(data, &maping)
	if err != nil {
		log.Printf("GetAccounts: unable to parse json: %s", err)
		return nil, fmt.Errorf("GetAccounts: unable to parse json: %s", err)
	}

	var coreAccounts []AccountResponse
	for _, ca := range maping {
		if ca.ID != "" {
			cat := AccountResponse{ID: ca.ID, Name: ca.Profile.FirstName}
			coreAccounts = append(coreAccounts, cat)
		}

	}

	return coreAccounts, nil
}

// NewService creates and configures a new Service instance
func NewService(serviceAccountManager *auth.ServiceAccountManager, deletedAccountsConfig *DeletedAccountsConfig, logger *logs.Logger) (*Service, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	if deletedAccountsConfig != nil {
		deletedAccountsConfig.path = "/tps/deleted-accounts"
		if serviceAccountManager.AuthService.FirstParty {
			deletedAccountsConfig.path = "/bbs/deleted-accounts"
		}

		if deletedAccountsConfig.Callback != nil {
			deletedAccountsConfig.timerDone = make(chan bool)
			if deletedAccountsConfig.Period == 0 {
				deletedAccountsConfig.Period = 2
			}
		}
	}

	core := Service{serviceAccountManager: serviceAccountManager, deletedAccountsConfig: deletedAccountsConfig, logger: logger}
	return &core, nil
}

// DeletedAccountsConfig represents a configuration for getting deleted accounts from a remote core service
type DeletedAccountsConfig struct {
	Callback func([]string) error // Function to call once the deleted accounts are received
	Period   uint                 // How often to request deleted account list in hours (the default is 2)

	path      string
	timerDone chan bool
	timer     *time.Timer
}

// Account wraps the account structure from the Core BB
// @name Account
type Account struct {
	AuthTypes []struct {
		Active       bool   `json:"active"`
		AuthTypeCode string `json:"auth_type_code"`
		AuthTypeID   string `json:"auth_type_id"`
		Identifier   string `json:"identifier"`
		Params       struct {
			User struct {
				Email          string        `json:"email"`
				FirstName      string        `json:"first_name"`
				Groups         []interface{} `json:"groups"`
				Identifier     string        `json:"identifier"`
				LastName       string        `json:"last_name"`
				MiddleName     string        `json:"middle_name"`
				Roles          []string      `json:"roles"`
				SystemSpecific struct {
					PreferredUsername string `json:"preferred_username"`
				} `json:"system_specific"`
			} `json:"user"`
		} `json:"params"`
	} `json:"auth_types"`
	Profile struct {
		Address   string `json:"address"`
		BirthYear int    `json:"birth_year"`
		Country   string `json:"country"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		ID        string `json:"id"`
		LastName  string `json:"last_name"`
		Phone     string `json:"phone"`
		PhotoURL  string `json:"photo_url"`
		State     string `json:"state"`
		ZipCode   string `json:"zip_code"`
	} `json:"profile"`
	ID string `json:"id"`
}

// AccountResponse wraps the accountID and first name of the account
// @name AccountResponse
type AccountResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
