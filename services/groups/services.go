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
	"errors"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

// GroupsService contains configurations and helper functions required to utilize certain core services
type GroupsAdapter struct {
	serviceAccountManager *auth.ServiceAccountManager

	GroupsAdapter string

	logger *logs.Logger
}

// NewGroupsService creates and configures a new Service instance
func NewGroupsService(serviceAccountManager *auth.ServiceAccountManager, groupsBaseURL string, logger *logs.Logger) (*GroupsAdapter, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	groups := GroupsAdapter{serviceAccountManager: serviceAccountManager, GroupsAdapter: groupsBaseURL, logger: logger}

	return &groups, nil
}
