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

package notifications

import (
	"errors"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

// NotificationsAdapter contains configurations and helper functions required to utilize certain core services
type NotificationsAdapter struct {
	serviceAccountManager *auth.ServiceAccountManager

	notificationsBaseURL string

	logger *logs.Logger
}

// NewNotificationsService creates and configures a new Service instance
func NewNotificationsService(serviceAccountManager *auth.ServiceAccountManager, notificationsBaseURL string, logger *logs.Logger) (*NotificationsAdapter, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	if notificationsBaseURL == "" {
		return nil, errors.New("notifications base url is missing")
	}

	groups := NotificationsAdapter{serviceAccountManager: serviceAccountManager, notificationsBaseURL: notificationsBaseURL, logger: logger}

	return &groups, nil
}
