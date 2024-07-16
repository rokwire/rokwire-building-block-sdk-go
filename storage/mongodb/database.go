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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

// Collection gets a handle for a MongoDB collection with the given name configured with the given CollectionOptions
func (d *Database) Collection(name string, opts ...*options.CollectionOptions) *mongo.Collection {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Collection(name, opts...)
}

func (d *Database) start() error {

	d.Logger.Info("database -> start")

	//connect to the database
	clientOptions := options.Client().ApplyURI(d.MongoDBAuth)
	connectContext, cancel := context.WithTimeout(context.Background(), d.MongoTimeout)
	client, err := mongo.Connect(connectContext, clientOptions)
	cancel()
	if err != nil {
		return err
	}

	//ping the database
	pingContext, cancel := context.WithTimeout(context.Background(), d.MongoTimeout)
	err = client.Ping(pingContext, nil)
	cancel()
	if err != nil {
		return err
	}

	//assign the db, db client and the collections
	db := client.Database(d.MongoDBName)
	d.db = db
	d.dbClient = client

	err = d.setupConfigsCollection()
	if err != nil {
		return err
	}

	return nil
}

func (d *Database) setupConfigsCollection() error {
	d.Logger.Info("setup configs collection.....")
	configs := &CollectionWrapper{Database: d, Coll: d.db.Collection("configs")}

	err := configs.AddIndex(nil, bson.D{primitive.E{Key: "type", Value: 1}, primitive.E{Key: "app_id", Value: 1}, primitive.E{Key: "org_id", Value: 1}}, true)
	if err != nil {
		return err
	}

	d.configs = configs
	go d.configs.Watch(nil, d.Logger)

	d.Logger.Info("configs setup passed")
	return nil
}
