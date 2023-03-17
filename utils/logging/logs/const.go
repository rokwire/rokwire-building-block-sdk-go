// Copyright 2021 Board of Trustees of the University of Illinois
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

package logs

import (
	"strings"
)

// LogLevel represents the level of logging to be performed
type LogLevel string

// LogLevelFromString takes a string (not case-sensitive) and returns the equivalent logLevel. Options are "debug", "info", "warn", and "error"
func LogLevelFromString(level string) *LogLevel {
	var lLevel LogLevel

	switch strings.ToLower(level) {
	case strings.ToLower(string(Debug)):
		lLevel = Debug
	case strings.ToLower(string(Info)):
		lLevel = Info
	case strings.ToLower(string(Warn)):
		lLevel = Warn
	case strings.ToLower(string(Error)):
		lLevel = Error
	}

	return &lLevel
}

const (
	// Levels

	// Info log level
	Info LogLevel = "Info"
	// Debug log level
	Debug LogLevel = "Debug"
	// Warn log level
	Warn LogLevel = "Warn"
	// Error log level
	Error LogLevel = "Error"
)
