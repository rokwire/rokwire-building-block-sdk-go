// Copyright 2023 Board of Trustees of the University of Illinois.
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

package web

import (
	"github.com/rokwire/rokwire-building-block-sdk-go/services/common"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/tokenauth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/rokwireutils"
)

type adminReqUpdateConfigs struct {
	AllApps *bool       `json:"all_apps,omitempty"`
	AllOrgs *bool       `json:"all_orgs,omitempty"`
	Data    interface{} `json:"data"`
	System  bool        `json:"system"`
	Type    string      `json:"type"`
}

func configFromRequest(claims *tokenauth.Claims, item *adminReqUpdateConfigs) (*common.Config, error) {
	if item == nil {
		return nil, nil
	}

	appID := claims.AppID
	if item.AllApps != nil && *item.AllApps {
		appID = rokwireutils.AllApps
	}
	orgID := claims.OrgID
	if item.AllOrgs != nil && *item.AllOrgs {
		orgID = rokwireutils.AllOrgs
	}

	return &common.Config{Type: item.Type, AppID: appID, OrgID: orgID, System: item.System, Data: item.Data}, nil
}
