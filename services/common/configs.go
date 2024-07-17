// Copyright 2024 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/tokenauth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/errors"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/rokwireutils"
)

const (
	// TypeConfig configs type
	TypeConfig logutils.MessageDataType = "config"
	// TypeConfigData config data type
	TypeConfigData logutils.MessageDataType = "config data"
)

// Config contain generic configs
type Config struct {
	ID          string      `json:"id" bson:"_id"`
	Type        string      `json:"type" bson:"type"`
	AppID       string      `json:"app_id" bson:"app_id"`
	OrgID       string      `json:"org_id" bson:"org_id"`
	System      bool        `json:"system" bson:"system"`
	Data        interface{} `json:"data" bson:"data"`
	DateCreated time.Time   `json:"date_created" bson:"date_created"`
	DateUpdated *time.Time  `json:"date_updated" bson:"date_updated"`
}

// GetConfig retrieves a single configs by its ID and determines if the user may access it
func (a appAdmin) GetConfig(claims *tokenauth.Claims, id string) (*Config, error) {
	config, err := a.app.Storage.FindConfigByID(id)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, TypeConfig, nil, err)
	}
	if config == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, TypeConfig, &logutils.FieldArgs{"id": id})
	}

	err = claims.CanAccess(config.AppID, config.OrgID, config.System)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, "config access", nil, err)
	}

	return config, nil
}

// GetConfigs retrieves a list of configs and returns a list of those the user may access
func (a appAdmin) GetConfigs(claims *tokenauth.Claims, configType *string) ([]Config, error) {
	configs, err := a.app.Storage.FindConfigs(configType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, TypeConfig, nil, err)
	}

	allowedConfigs := make([]Config, 0)
	for _, config := range configs {
		if err := claims.CanAccess(config.AppID, config.OrgID, config.System); err == nil {
			allowedConfigs = append(allowedConfigs, config)
		}
	}
	return allowedConfigs, nil
}

// CreateConfig creates a new config if the user has appropriate access
func (a appAdmin) CreateConfig(claims *tokenauth.Claims, item Config) (*Config, error) {
	// must be a system config if applying to all orgs
	if item.OrgID == rokwireutils.AllOrgs && !item.System {
		return nil, errors.ErrorData(logutils.StatusInvalid, "config system status", &logutils.FieldArgs{"config.org_id": rokwireutils.AllOrgs})
	}

	err := claims.CanAccess(item.AppID, item.OrgID, item.System)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, "config access", nil, err)
	}

	item.ID = uuid.NewString()
	item.DateCreated = time.Now().UTC()
	err = a.app.Storage.InsertConfig(item)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, TypeConfig, nil, err)
	}

	config := item
	return &config, nil
}

// UpdateConfig updates an exisitng config if the user has appropriate access
func (a appAdmin) UpdateConfig(claims *tokenauth.Claims, id string, item Config) (*Config, error) {
	// must be a system config if applying to all orgs
	if item.OrgID == rokwireutils.AllOrgs && !item.System {
		return nil, errors.ErrorData(logutils.StatusInvalid, "config system status", &logutils.FieldArgs{"config.org_id": rokwireutils.AllOrgs})
	}

	oldConfig, err := a.app.Storage.FindConfig(item.Type, item.AppID, item.OrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, TypeConfig, nil, err)
	}
	if oldConfig == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, TypeConfig, &logutils.FieldArgs{"type": item.Type, "app_id": item.AppID, "org_id": item.OrgID})
	}

	// cannot update a system config if not a system admin
	if !claims.System && oldConfig.System {
		return nil, errors.ErrorData(logutils.StatusInvalid, "system claim", nil)
	}
	err = claims.CanAccess(item.AppID, item.OrgID, item.System)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, "config access", nil, err)
	}

	now := time.Now().UTC()
	item.ID = oldConfig.ID
	item.DateUpdated = &now

	err = a.app.Storage.UpdateConfig(item)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, TypeConfig, nil, err)
	}

	return nil, nil
}

// DeleteConfig removes an existing config if the user has appropriate access
func (a appAdmin) DeleteConfig(claims *tokenauth.Claims, id string) error {
	config, err := a.app.Storage.FindConfigByID(id)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, TypeConfig, nil, err)
	}
	if config == nil {
		return errors.ErrorData(logutils.StatusMissing, TypeConfig, &logutils.FieldArgs{"id": id})
	}

	err = claims.CanAccess(config.AppID, config.OrgID, config.System)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "config access", nil, err)
	}

	err = a.app.Storage.DeleteConfig(id)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, TypeConfig, nil, err)
	}
	return nil
}
