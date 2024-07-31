// Copyright 2024 Board of Trustees of the University of Illinois.
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

package common

import (
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

// Application represents the core application code based on hexagonal architecture
type Application[T Storage] struct {
	Version string
	Build   string

	Default Default // expose to the drivers adapters
	Admin   Admin   // expose to the drivers adapters

	Logger *logs.Logger

	Storage T
}

// appDefault contains default implementations
type appDefault[T Storage] struct {
	app *Application[T]
}

// GetVersion gets the current version of this service
func (a appDefault[T]) GetVersion() (*string, error) {
	return &a.app.Version, nil
}

// appAdmin contains admin implementations
type appAdmin[T Storage] struct {
	app *Application[T]
}

// NewApplication creates new Application
func NewApplication[T Storage](version string, build string, storage T, logger *logs.Logger) *Application[T] {
	application := Application[T]{Version: version, Build: build, Storage: storage, Logger: logger}

	//add the drivers ports/interfaces
	application.Default = appDefault[T]{app: &application}
	application.Admin = appAdmin[T]{app: &application}

	return &application
}
