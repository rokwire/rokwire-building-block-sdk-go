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

func GetConfig(storage Storage, claims *tokenauth.Claims, id string) (*Config, error) {
	config, err := storage.FindConfigByID(id)
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

func GetConfigs(storage Storage, claims *tokenauth.Claims, configType *string) ([]Config, error) {
	configs, err := storage.FindConfigs(configType)
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

func CreateConfig(storage Storage, claims *tokenauth.Claims, item Config) (*Config, error) {
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
	err = storage.InsertConfig(item)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, TypeConfig, nil, err)
	}

	config := item
	return &config, nil
}

func UpdateConfig(storage Storage, claims *tokenauth.Claims, id string, item Config) (*Config, error) {
	// must be a system config if applying to all orgs
	if item.OrgID == rokwireutils.AllOrgs && !item.System {
		return nil, errors.ErrorData(logutils.StatusInvalid, "config system status", &logutils.FieldArgs{"config.org_id": rokwireutils.AllOrgs})
	}

	oldConfig, err := storage.FindConfig(item.Type, item.AppID, item.OrgID)
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

	err = storage.UpdateConfig(item)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, TypeConfig, nil, err)
	}

	return nil, nil
}

func DeleteConfig(storage Storage, claims *tokenauth.Claims, id string) error {
	config, err := storage.FindConfigByID(id)
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

	err = storage.DeleteConfig(id)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, TypeConfig, nil, err)
	}
	return nil
}
