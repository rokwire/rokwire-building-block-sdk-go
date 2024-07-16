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
	"context"
	"sync"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/common"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/errors"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/sync/syncmap"
)

// Adapter implements the Storage interface
type Adapter struct {
	db *Database

	Context mongo.SessionContext

	configDataParser func(*common.Config) error
	cachedConfigs    *syncmap.Map
	configsLock      *sync.RWMutex
}

// Start starts the storage
func (a *Adapter) Start(sl common.StorageListener) error {
	err := a.db.start()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInitialize, "storage adapter", nil, err)
	}

	//register storage listener
	a.RegisterStorageListener(sl)

	//cache the configs
	err = a.cacheConfigs()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCache, common.TypeConfig, nil, err)
	}

	return nil
}

// RegisterStorageListener registers a data change listener with the storage adapter
func (a *Adapter) RegisterStorageListener(listener common.StorageListener) {
	a.db.Listeners = append(a.db.Listeners, listener)
}

// Creates a new Adapter with provided context
func (a *Adapter) WithContext(context mongo.SessionContext) common.Storage {
	return &Adapter{db: a.db, Context: context, cachedConfigs: a.cachedConfigs, configsLock: a.configsLock}
}

func (a *Adapter) StartSession() (mongo.Session, error) {
	return a.db.dbClient.StartSession()
}

type StorageContext[T common.Storage] interface {
	WithContext(context mongo.SessionContext) T
	StartSession() (mongo.Session, error)
}

// PerformTransaction performs a transaction
func PerformTransaction[T common.Storage](sc StorageContext[T], transaction func(storage T) error) error {
	// transaction
	callback := func(sessionContext mongo.SessionContext) (interface{}, error) {
		adapter := sc.WithContext(sessionContext)

		err := transaction(adapter)
		if err != nil {
			if wrappedErr, ok := err.(*errors.Error); ok && wrappedErr.Internal() != nil {
				return nil, wrappedErr.Internal()
			}
			return nil, err
		}

		return nil, nil
	}

	session, err := sc.StartSession()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionStart, "mongo session", nil, err)
	}
	context := context.Background()
	defer session.EndSession(context)

	_, err = session.WithTransaction(context, callback)
	if err != nil {
		return errors.WrapErrorAction("performing", logutils.TypeTransaction, nil, err)
	}
	return nil
}

func FilterArgs(filter bson.M) *logutils.FieldArgs {
	args := logutils.FieldArgs{}
	for k, v := range filter {
		args[k] = v
	}
	return &args
}

// NewStorageAdapter creates a new storage adapter instance
func NewStorageAdapter(db *Database, configDataParser func(*common.Config) error) *Adapter {
	cachedConfigs := &syncmap.Map{}
	configsLock := &sync.RWMutex{}

	return &Adapter{db: db, cachedConfigs: cachedConfigs, configsLock: configsLock, configDataParser: configDataParser}
}
