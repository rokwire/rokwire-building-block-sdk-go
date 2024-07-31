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

package mongodb

import (
	"fmt"
	"strings"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/common"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/errors"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/sync/syncmap"
)

// cacheConfigs caches the configs from the DB
func (a *Adapter) cacheConfigs() error {
	a.db.Logger.Info("cacheConfigs...")

	configs, err := a.loadConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionLoad, common.TypeConfig, nil, err)
	}

	a.setCachedConfigs(configs)

	return nil
}

func (a *Adapter) setCachedConfigs(configs []common.Config) {
	a.configsLock.Lock()
	defer a.configsLock.Unlock()

	a.cachedConfigs = &syncmap.Map{}

	for _, config := range configs {
		err := a.configDataParser(&config)
		if err != nil {
			a.db.Logger.Warn(err.Error())
		}
		a.cachedConfigs.Store(config.ID, config)
		a.cachedConfigs.Store(fmt.Sprintf("%s_%s_%s", config.Type, config.AppID, config.OrgID), config)
	}
}

func (a *Adapter) getCachedConfig(id string, configType string, appID string, orgID string) (*common.Config, error) {
	a.configsLock.RLock()
	defer a.configsLock.RUnlock()

	var item any
	var errArgs logutils.FieldArgs
	if id != "" {
		errArgs = logutils.FieldArgs{"id": id}
		item, _ = a.cachedConfigs.Load(id)
	} else {
		errArgs = logutils.FieldArgs{"type": configType, "app_id": appID, "org_id": orgID}
		item, _ = a.cachedConfigs.Load(fmt.Sprintf("%s_%s_%s", configType, appID, orgID))
	}

	if item != nil {
		config, ok := item.(common.Config)
		if !ok {
			return nil, errors.ErrorAction(logutils.ActionCast, common.TypeConfig, &errArgs)
		}
		return &config, nil
	}
	return nil, nil
}

func (a *Adapter) getCachedConfigs(configType *string) ([]common.Config, error) {
	a.configsLock.RLock()
	defer a.configsLock.RUnlock()

	var err error
	configList := make([]common.Config, 0)
	a.cachedConfigs.Range(func(key, item interface{}) bool {
		keyStr, ok := key.(string)
		if !ok || item == nil {
			return false
		}
		if !strings.Contains(keyStr, "_") {
			return true
		}

		config, ok := item.(common.Config)
		if !ok {
			err = errors.ErrorAction(logutils.ActionCast, common.TypeConfig, &logutils.FieldArgs{"key": key})
			return false
		}

		if configType == nil || strings.HasPrefix(keyStr, fmt.Sprintf("%s_", *configType)) {
			configList = append(configList, config)
		}

		return true
	})

	return configList, err
}

// loadConfigs loads configs
func (a *Adapter) loadConfigs() ([]common.Config, error) {
	filter := bson.M{}

	var configs []common.Config
	err := a.db.configs.Find(a.Context, filter, &configs, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, common.TypeConfig, nil, err)
	}

	return configs, nil
}

// FindConfig finds the config for the specified type, appID, and orgID
func (a *Adapter) FindConfig(configType string, appID string, orgID string) (*common.Config, error) {
	return a.getCachedConfig("", configType, appID, orgID)
}

// FindConfigByID finds the config for the specified ID
func (a *Adapter) FindConfigByID(id string) (*common.Config, error) {
	return a.getCachedConfig(id, "", "", "")
}

// FindConfigs finds all configs for the specified type
func (a *Adapter) FindConfigs(configType *string) ([]common.Config, error) {
	return a.getCachedConfigs(configType)
}

// InsertConfig inserts a new config
func (a *Adapter) InsertConfig(config common.Config) error {
	_, err := a.db.configs.InsertOne(a.Context, config)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, common.TypeConfig, nil, err)
	}

	return nil
}

// UpdateConfig updates an existing config
func (a *Adapter) UpdateConfig(config common.Config) error {
	filter := bson.M{"_id": config.ID}
	update := bson.D{
		primitive.E{Key: "$set", Value: bson.D{
			primitive.E{Key: "type", Value: config.Type},
			primitive.E{Key: "app_id", Value: config.AppID},
			primitive.E{Key: "org_id", Value: config.OrgID},
			primitive.E{Key: "system", Value: config.System},
			primitive.E{Key: "data", Value: config.Data},
			primitive.E{Key: "date_updated", Value: config.DateUpdated},
		}},
	}
	_, err := a.db.configs.UpdateOne(a.Context, filter, update, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, common.TypeConfig, &logutils.FieldArgs{"id": config.ID}, err)
	}

	return nil
}

// DeleteConfig deletes a configuration from storage
func (a *Adapter) DeleteConfig(id string) error {
	delFilter := bson.M{"_id": id}
	_, err := a.db.configs.DeleteMany(a.Context, delFilter, nil)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, common.TypeConfig, &logutils.FieldArgs{"id": id}, err)
	}

	return nil
}
