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
	"time"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/common"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Database represents a wrapper for a connection to a MongoDB instance
type Database struct {
	MongoDBAuth  string
	MongoDBName  string
	MongoTimeout time.Duration
	Logger       *logs.Logger

	db       *mongo.Database
	dbClient *mongo.Client

	configs *CollectionWrapper

	OnDataChanged func(string)
	Listeners     []common.StorageListener
}

func (d *Database) Collection(name string, opts ...options.Lister[options.CollectionOptions]) *mongo.Collection {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Collection(name, opts...)
}

func (d *Database) start() error {
	d.Logger.Info("database -> start")

	// connect to the database (v2: Connect does not take context)
	clientOptions := options.Client().
		ApplyURI(d.MongoDBAuth).
		SetTimeout(d.MongoTimeout)

	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return err
	}

	// ping the database (use context here)
	pingContext, cancel := context.WithTimeout(context.Background(), d.MongoTimeout)
	defer cancel()

	if err := client.Ping(pingContext, nil); err != nil {
		return err
	}

	// assign the db, db client and the collections
	d.db = client.Database(d.MongoDBName)
	d.dbClient = client

	if err := d.setupConfigsCollection(); err != nil {
		return err
	}

	return nil
}

func (d *Database) setupConfigsCollection() error {
	d.Logger.Info("setup configs collection.....")
	configs := &CollectionWrapper{Database: d, Coll: d.db.Collection("configs")}

	err := configs.AddIndex(nil, bson.D{
		{Key: "type", Value: 1},
		{Key: "app_id", Value: 1},
		{Key: "org_id", Value: 1},
	}, true)
	if err != nil {
		return err
	}

	d.configs = configs
	go d.configs.Watch(nil, d.Logger)

	d.Logger.Info("configs setup passed")
	return nil
}

func (d *Database) onDataChanged(changeDoc map[string]interface{}) {
	if changeDoc == nil {
		return
	}
	d.Logger.Infof("onDataChanged: %+v\n", changeDoc)

	ns := changeDoc["ns"]
	if ns == nil {
		return
	}
	nsMap := ns.(map[string]interface{})
	coll, ok := nsMap["coll"].(string)
	if !ok {
		return
	}

	switch coll {
	case "configs":
		d.Logger.Info("configs collection changed")
		for _, listener := range d.Listeners {
			go listener.OnConfigsUpdated()
		}
	default:
		d.OnDataChanged(coll)
	}
}
