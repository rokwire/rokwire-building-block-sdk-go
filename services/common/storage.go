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

// Storage is used by core to storage data - DB storage adapter, file storage adapter etc
type Storage interface {
	RegisterStorageListener(listener StorageListener)

	FindConfig(configType string, appID string, orgID string) (*Config, error)
	FindConfigByID(id string) (*Config, error)
	FindConfigs(configType *string) ([]Config, error)
	InsertConfig(config Config) error
	UpdateConfig(config Config) error
	DeleteConfig(id string) error
}

// StorageListener represents storage listener
type StorageListener interface {
	OnConfigsUpdated()
}
