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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// CollectionWrapper wraps a MongoDB collection with additional database settings
type CollectionWrapper struct {
	Database *Database
	Coll     *mongo.Collection
}

// Find performs a Find operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) Find(ctx context.Context, filter interface{}, result interface{},
	findOptions *options.FindOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	if filter == nil {
		// Passing bson.D{} as the filter matches all documents in the collection
		filter = bson.D{}
	}

	cur, err := collWrapper.Coll.Find(ctx, filter, findOptions)

	if err == nil {
		err = cur.All(ctx, result)
	}

	return err
}

// FindOne performs a FindOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) FindOne(ctx context.Context, filter interface{}, result interface{}, findOptions *options.FindOneOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	if findOptions == nil {
		findOptions = options.FindOne() // crash if not added!
	}

	singleResult := collWrapper.Coll.FindOne(ctx, filter, findOptions)
	if singleResult.Err() != nil {
		return singleResult.Err()
	}
	err := singleResult.Decode(result)
	if err != nil {
		return err
	}
	return nil
}

// ReplaceOne performs a ReplaceOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) ReplaceOne(ctx context.Context, filter interface{}, replacement interface{}, replaceOptions *options.ReplaceOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	if replacement == nil {
		return errors.New("replace one - input parameters cannot be nil")
	}
	if replaceOptions == nil {
		replaceOptions = options.Replace() // crash if not added!
	}

	res, err := collWrapper.Coll.ReplaceOne(ctx, filter, replacement, replaceOptions)
	if err != nil {
		return err
	}
	if res == nil {
		return errors.New("replace one - res is nil")
	}
	if replaceOptions.Upsert == nil || !*replaceOptions.Upsert {
		matchedCount := res.MatchedCount
		if matchedCount == 0 {
			return errors.New("replace one - no record replaced")
		}
	}

	return nil
}

// InsertOne performs an InsertOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) InsertOne(ctx context.Context, data interface{}) (interface{}, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)

	ins, err := collWrapper.Coll.InsertOne(ctx, data)
	cancel()

	if err == nil {
		return ins.InsertedID, nil
	}

	return nil, err
}

// InsertMany performs an InsertMany operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) InsertMany(ctx context.Context, documents []interface{}, opts *options.InsertManyOptions) (*mongo.InsertManyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	result, err := collWrapper.Coll.InsertMany(ctx, documents, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteMany performs a Delete operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) DeleteMany(ctx context.Context, filter interface{}, opts *options.DeleteOptions) (*mongo.DeleteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	result, err := collWrapper.Coll.DeleteMany(ctx, filter, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// DeleteOne performs a DeleteOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) DeleteOne(ctx context.Context, filter interface{}, opts *options.DeleteOptions) (*mongo.DeleteResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	result, err := collWrapper.Coll.DeleteOne(ctx, filter, opts)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateOne performs an UpdateOne operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) UpdateOne(ctx context.Context, filter interface{}, update interface{}, opts *options.UpdateOptions) (*mongo.UpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	updateResult, err := collWrapper.Coll.UpdateOne(ctx, filter, update, opts)
	if err != nil {
		return nil, err
	}

	return updateResult, nil
}

// UpdateMany performs an UpdateMany operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) UpdateMany(ctx context.Context, filter interface{}, update interface{}, opts *options.UpdateOptions) (*mongo.UpdateResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	updateResult, err := collWrapper.Coll.UpdateMany(ctx, filter, update, opts)
	if err != nil {
		return nil, err
	}

	return updateResult, nil
}

// FindOneAndUpdate performs a FindOneAndUpdate operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) FindOneAndUpdate(ctx context.Context, filter interface{}, update interface{}, result interface{}, opts *options.FindOneAndUpdateOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	singleResult := collWrapper.Coll.FindOneAndUpdate(ctx, filter, update, opts)
	if singleResult.Err() != nil {
		return singleResult.Err()
	}
	err := singleResult.Decode(result)
	if err != nil {
		return err
	}
	return nil
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

	count, err := collWrapper.Coll.CountDocuments(ctx, filter)

	if err != nil {
		return -1, err
	}
	return count, nil
}

// Aggregate performs an Aggregate operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) Aggregate(ctx context.Context, pipeline interface{}, result interface{}, ops *options.AggregateOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Millisecond*15000)
	defer cancel()

	cursor, err := collWrapper.Coll.Aggregate(ctx, pipeline, ops)

	if err == nil {
		err = cursor.All(ctx, result)
	}

	return err
}

// ListIndexes performs a ListIndexes operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) ListIndexes(ctx context.Context, l *logs.Logger) ([]bson.M, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Millisecond*15000)
	defer cancel()

	indexes, err := collWrapper.Coll.Indexes().List(ctx, nil)
	if err != nil {
		l.Errorf("error getting indexes list: %s\n", err)
		return nil, err
	}

	var list []bson.M
	err = indexes.All(ctx, &list)
	if err != nil {
		l.Errorf("error iterating indexes list: %s\n", err)
		return nil, err
	}
	return list, nil
}

// AddIndex performs an AddIndex operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) AddIndex(ctx context.Context, keys interface{}, unique bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Millisecond*15000)
	defer cancel()

	index := mongo.IndexModel{Keys: keys}

	if unique {
		index.Options = options.Index()
		index.Options.Unique = &unique
	}

	_, err := collWrapper.Coll.Indexes().CreateOne(ctx, index, nil)

	return err
}

// AddIndexWithOptions performs an AddIndexWithOptions operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) AddIndexWithOptions(ctx context.Context, keys interface{}, opt *options.IndexOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Millisecond*15000)
	defer cancel()

	index := mongo.IndexModel{Keys: keys}
	index.Options = opt

	_, err := collWrapper.Coll.Indexes().CreateOne(ctx, index, nil)

	return err
}

// DropIndex performs a DropIndex operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) DropIndex(ctx context.Context, name string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Millisecond*15000)
	defer cancel()

	_, err := collWrapper.Coll.Indexes().DropOne(ctx, name, nil)

	return err
}

// Drop performs a Drop operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) Drop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, collWrapper.Database.MongoTimeout)
	defer cancel()

	err := collWrapper.Coll.Drop(ctx)
	if err != nil {
		return err
	}
	return nil
}

// Watch performs a Watch operation on the underlying MongoDB collection
func (collWrapper *CollectionWrapper) Watch(pipeline interface{}, l *logs.Logger) {
	var rt bson.Raw
	var err error
	for {
		rt, err = collWrapper.watch(pipeline, rt, l)
		if err != nil {
			l.Errorf("mongo watch error: %s\n", err.Error())
		}
	}
}

// Helper function for Watch
func (collWrapper *CollectionWrapper) watch(pipeline interface{}, resumeToken bson.Raw, l *logs.Logger) (bson.Raw, error) {
	if pipeline == nil {
		pipeline = []bson.M{}
	}

	opts := options.ChangeStream()
	opts.SetFullDocument(options.UpdateLookup)
	if resumeToken != nil {
		opts.SetResumeAfter(resumeToken)
	}

	ctx := context.Background()
	cur, err := collWrapper.Coll.Watch(ctx, pipeline, opts)
	if err != nil {
		time.Sleep(time.Second * 3)
		return nil, fmt.Errorf("error watching: %s", err)
	}
	defer cur.Close(ctx)

	var changeDoc map[string]interface{}
	l.Infof("%s: waiting for changes\n", collWrapper.Coll.Name())
	for cur.Next(ctx) {
		if e := cur.Decode(&changeDoc); e != nil {
			l.Errorf("error decoding: %s\n", e)
		}
		collWrapper.Database.onDataChanged(changeDoc)
	}

	if err := cur.Err(); err != nil {
		return cur.ResumeToken(), fmt.Errorf("error cur.Err(): %s", err)
	}

	return cur.ResumeToken(), errors.New("unknown error occurred")
}
