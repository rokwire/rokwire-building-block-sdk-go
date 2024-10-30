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

package groups

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

// GroupAdapter contains configurations and helper functions required to utilize certain core services
type GroupAdapter struct {
	serviceAccountManager *auth.ServiceAccountManager

	groupsBaseURL string

	logger *logs.Logger
}

// GetGroupMembership wrapps the group title and group membership status of user
type GetGroupMembership struct {
	GroupID string `json:"group_id"`
	Title   string `json:"group_title"`
	Status  string `json:"status"`
}

// GetGroupMemberships Get aggregated title of the group and status of the member
func (na *GroupAdapter) GetGroupMemberships(logs logs.Logger, userID string) ([]GetGroupMembership, error) {
	url := fmt.Sprintf("%s/api/bbs/groups/%s/memberships", na.groupsBaseURL, userID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logs.Errorf("GetGroupMembership:error creating load user data request - %s", err)
		return nil, err
	}

	resp, err := na.serviceAccountManager.MakeRequest(req, "all", "all")
	if err != nil {
		logs.Errorf("GetGroupMembership: error sending request - %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errorResponse, _ := ioutil.ReadAll(resp.Body)
		if errorResponse != nil {
			logs.Errorf("GetGroupMembership: error with response code - %s", errorResponse)
		}
		logs.Errorf("GetGroupMembership: error with response code - %d", resp.StatusCode)
		return nil, fmt.Errorf("GetGroupEventUsers:error with response code != 200")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("GetGroupMembership: unable to read json: %s", err)
		return nil, fmt.Errorf("GetGroupMembership: unable to parse json: %s", err)
	}

	var getGroupMemberships []GetGroupMembership
	err = json.Unmarshal(data, &getGroupMemberships)
	if err != nil {
		log.Printf("GetGroupMembership: unable to parse json: %s", err)
		return nil, fmt.Errorf("GetGroupMembership: unable to parse json: %s", err)
	}

	return getGroupMemberships, nil
}

// GetGroupMembershipsByGroupID Get group memebers by groupID
func (na *GroupAdapter) GetGroupMembershipsByGroupID(logs logs.Logger, groupID string) ([]string, error) {
	url := fmt.Sprintf("%s/api/bbs/groups/%s/group-memberships", na.groupsBaseURL, groupID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logs.Errorf("GetGroupMembershipsByGroupID:error creating load user data request - %s", err)
		return nil, err
	}

	resp, err := na.serviceAccountManager.MakeRequest(req, "all", "all")
	if err != nil {
		logs.Errorf("GetGroupMembershipsByGroupID: error sending request - %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errorResponse, _ := ioutil.ReadAll(resp.Body)
		if errorResponse != nil {
			logs.Errorf("GetGroupMembershipsByGroupID: error with response code - %s", errorResponse)
		}
		logs.Errorf("GetGroupMembershipsByGroupID: error with response code - %d", resp.StatusCode)
		return nil, fmt.Errorf("GetGroupMembershipsByGroupID:error with response code != 200")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("GetGroupMembershipsByGroupID: unable to read json: %s", err)
		return nil, fmt.Errorf("GetGroupMembershipsByGroupID: unable to parse json: %s", err)
	}

	var groupMembers []string
	err = json.Unmarshal(data, &groupMembers)
	if err != nil {
		log.Printf("GetGroupMembershipsByGroupID: unable to parse json: %s", err)
		return nil, fmt.Errorf("GetGroupMembershipsByGroupID: unable to parse json: %s", err)
	}

	return groupMembers, nil
}

// NewGroupsService creates and configures a new Service instance
func NewGroupsService(serviceAccountManager *auth.ServiceAccountManager, groupsBaseURL string, logger *logs.Logger) (*GroupAdapter, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	if groupsBaseURL == "" {
		return nil, errors.New("groups base url is missing")
	}

	groups := GroupAdapter{serviceAccountManager: serviceAccountManager, groupsBaseURL: groupsBaseURL, logger: logger}

	return &groups, nil
}
