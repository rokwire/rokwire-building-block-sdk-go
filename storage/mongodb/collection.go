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
	"errors"
	"fmt"
	"time"

	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// CollectionWrapper wraps a MongoDB collection with additional database settings
type CollectionWrapper struct {
	Database *Database
	Coll     *mongo.Collection
}

func (collWrapper *CollectionWrapper) Find(
	ctx context.Context,
	filter interface{},
	result interface{},
	findOptions ...options.Lister[options.FindOptions],
) error {
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	if filter == nil {
		filter = bson.D{}
	}

	cur, err := collWrapper.Coll.Find(ctx, filter, findOptions...)
	if err != nil {
		return err
	}
	return cur.All(ctx, result)
}

// FindOne performs a FindOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) FindOne(ctx context.Context, filter interface{}, result interface{}, findOptions ...options.Lister[options.FindOneOptions],
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	singleResult := collWrapper.Coll.FindOne(ctx, filter, findOptions...)
	if singleResult.Err() != nil {
		return singleResult.Err()
	}
	return singleResult.Decode(result)
}

// ReplaceOne performs a ReplaceOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) ReplaceOne(ctx context.Context, filter interface{}, replacement interface{}, replaceOptions ...options.Lister[options.ReplaceOptions],
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	if replacement == nil {
		return errors.New("replace one - input parameters cannot be nil")
	}

	res, err := collWrapper.Coll.ReplaceOne(ctx, filter, replacement, replaceOptions...)
	if err != nil {
		return err
	}
	if res == nil {
		return errors.New("replace one - res is nil")
	}

	if res.MatchedCount == 0 && res.UpsertedCount == 0 {
		return errors.New("replace one - no record replaced")
	}

	return nil
}

// InsertOne performs an InsertOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) InsertOne(ctx context.Context, data interface{}) (interface{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	ins, err := collWrapper.Coll.InsertOne(ctx, data)
	if err != nil {
		return nil, err
	}

	return ins.InsertedID, nil
}

// InsertMany performs an InsertMany operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) InsertMany(ctx context.Context, documents []interface{}, opts ...options.Lister[options.InsertManyOptions],
) (*mongo.InsertManyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	return collWrapper.Coll.InsertMany(ctx, documents, opts...)
}

// DeleteMany performs a DeleteMany operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) DeleteMany(ctx context.Context, filter interface{}, opts ...options.Lister[options.DeleteManyOptions],
) (*mongo.DeleteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	return collWrapper.Coll.DeleteMany(ctx, filter, opts...)
}

// DeleteOne performs a DeleteOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) DeleteOne(ctx context.Context, filter interface{}, opts ...options.Lister[options.DeleteOneOptions],
) (*mongo.DeleteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	return collWrapper.Coll.DeleteOne(ctx, filter, opts...)
}

// UpdateOne performs an UpdateOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts ...options.Lister[options.UpdateOneOptions],
) (*mongo.UpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	return collWrapper.Coll.UpdateOne(ctx, filter, update, opts...)
}

// UpdateMany performs an UpdateMany operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) UpdateMany(ctx context.Context, filter interface{}, update interface{}, opts ...options.Lister[options.UpdateManyOptions],
) (*mongo.UpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	return collWrapper.Coll.UpdateMany(ctx, filter, update, opts...)
}

// FindOneAndUpdate performs a FindOneAndUpdate operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) FindOneAndUpdate(ctx context.Context, filter interface{}, update interface{}, result interface{}, opts ...options.Lister[options.FindOneAndUpdateOptions],
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	singleResult := collWrapper.Coll.FindOneAndUpdate(ctx, filter, update, opts...)
	if singleResult.Err() != nil {
		return singleResult.Err()
	}
	return singleResult.Decode(result)
}

// CountDocuments performs a CountDocuments operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) CountDocuments(ctx context.Context, filter interface{}) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	if filter == nil {
		filter = bson.D{}
	}

	return collWrapper.Coll.CountDocuments(ctx, filter)
}

// Aggregate performs an Aggregate operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) Aggregate(ctx context.Context, pipeline interface{}, result interface{}, ops ...options.Lister[options.AggregateOptions],
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cursor, err := collWrapper.Coll.Aggregate(ctx, pipeline, ops...)
	if err != nil {
		return err
	}

	return cursor.All(ctx, result)
}

// ListIndexes performs a ListIndexes operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) ListIndexes(ctx context.Context, l *logs.Logger) ([]bson.M, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	indexes, err := collWrapper.Coll.Indexes().List(ctx, nil)
	if err != nil {
		l.Errorf("error getting indexes list: %s", err)
		return nil, err
	}

	var list []bson.M
	if err := indexes.All(ctx, &list); err != nil {
		l.Errorf("error iterating indexes list: %s", err)
		return nil, err
	}
	return list, nil
}

// AddIndex performs an AddIndex operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) AddIndex(ctx context.Context, keys interface{}, unique bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	index := mongo.IndexModel{Keys: keys}

	if unique {
		index.Options = options.Index().SetUnique(true)
	}

	_, err := collWrapper.Coll.Indexes().CreateOne(ctx, index, nil)
	return err
}

// AddIndexWithOptions performs an AddIndexWithOptions operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) AddIndexWithOptions(ctx context.Context, keys interface{}, opt *options.IndexOptionsBuilder,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	index := mongo.IndexModel{Keys: keys, Options: opt}
	_, err := collWrapper.Coll.Indexes().CreateOne(ctx, index)
	return err
}

// DropIndex performs a DropIndex operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) DropIndex(ctx context.Context, name string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	return collWrapper.Coll.Indexes().DropOne(ctx, name)
}

// Drop performs a Drop operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) Drop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	return collWrapper.Coll.Drop(ctx)
}

// Watch performs a Watch operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) Watch(pipeline interface{}, l *logs.Logger) {
	var rt bson.Raw
	var err error
	for {
		rt, err = collWrapper.watch(pipeline, rt, l)
		if err != nil {
			l.Errorf("mongo watch error: %s", err.Error())
		}
	}
}

// Helper function for Watch
func (collWrapper *CollectionWrapper) watch(pipeline interface{}, resumeToken bson.Raw, l *logs.Logger) (bson.Raw, error) {
	if pipeline == nil {
		pipeline = []bson.M{}
	}

	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	if resumeToken != nil {
		opts.SetResumeAfter(resumeToken)
	}

	ctx := context.Background()
	cur, err := collWrapper.Coll.Watch(ctx, pipeline, opts)
	if err != nil {
		time.Sleep(3 * time.Second)
		return nil, fmt.Errorf("error watching: %s", err)
	}
	defer cur.Close(ctx)

	var changeDoc map[string]interface{}
	l.Infof("%s: waiting for changes", collWrapper.Coll.Name())
	for cur.Next(ctx) {
		if e := cur.Decode(&changeDoc); e != nil {
			l.Errorf("error decoding: %s", e)
		}
		collWrapper.Database.onDataChanged(changeDoc)
	}

	if err := cur.Err(); err != nil {
		return cur.ResumeToken(), fmt.Errorf("error cur.Err(): %s", err)
	}

	return cur.ResumeToken(), errors.New("unknown error occurred")
}
