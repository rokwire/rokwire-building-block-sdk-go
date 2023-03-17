// Copyright 2022 Board of Trustees of the University of Illinois
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
	"github.com/rokwire/rokwire-sdk-go/utils/logging/logutils"
	"github.com/sirupsen/logrus"
)

// Logger struct defines a wrapper for a logger object
type Logger struct {
	entry            *logrus.Entry
	sensitiveHeaders []string
	suppressRequests []HTTPRequestProperties
}

// LoggerOpts provides configuration options for the Logger type
type LoggerOpts struct {
	//JSONFmt: When true, logs will be output in JSON format. Otherwise logs will be in logfmt
	JSONFmt bool
	//SensitiveHeaders: A list of any headers that contain sensitive information and should not be logged
	//				    Defaults: Authorization, Csrf
	SensitiveHeaders []string
	//SuppressRequests: A list of HttpRequestProperties of requests that should not be logged
	//					Any "Warn" or higher severity logs will still be logged.
	//					This is useful to prevent info logs from health checks and similar requests from
	//					flooding the logs
	//					All specified fields in the provided HttpRequestProperties must match for the logs
	//					to be suppressed. Empty fields will be ignored.
	SuppressRequests []HTTPRequestProperties
}

// NewLogger is constructor for a logger object with initial configuration at the service level
// Params:
//
//	serviceName: A meaningful service name to be associated with all logs
//	opts: Configuration options for the Logger
func NewLogger(serviceName string, opts *LoggerOpts) *Logger {
	var baseLogger = logrus.New()
	sensitiveHeaders := []string{"Authorization", "Rokwire-Csrf-Token", "Cookie"}
	var suppressRequests []HTTPRequestProperties

	if opts != nil {
		if opts.JSONFmt {
			baseLogger.Formatter = &logrus.JSONFormatter{}
		} else {
			baseLogger.Formatter = &logrus.TextFormatter{}
		}

		sensitiveHeaders = append(sensitiveHeaders, opts.SensitiveHeaders...)
		suppressRequests = opts.SuppressRequests
	}

	standardFields := logrus.Fields{"service_name": serviceName} //All common fields for logs of a given service
	contextLogger := &Logger{entry: baseLogger.WithFields(standardFields), sensitiveHeaders: sensitiveHeaders, suppressRequests: suppressRequests}
	return contextLogger
}

// SetLevel sets the log level for the logger to the provided level
func (l *Logger) SetLevel(level LogLevel) {
	switch level {
	case Debug:
		l.entry.Logger.SetLevel(logrus.DebugLevel)
	case Info:
		l.entry.Logger.SetLevel(logrus.InfoLevel)
	case Warn:
		l.entry.Logger.SetLevel(logrus.WarnLevel)
	case Error:
		l.entry.Logger.SetLevel(logrus.ErrorLevel)
	default:
	}
}

func (l *Logger) withFields(fields logutils.Fields) *Logger {
	return &Logger{entry: l.entry.WithFields(fields.ToMap())}
}

// Fatal prints the log with a fatal error message and stops the service instance
// WARNING: Only use for critical error messages that should prevent the service from running
func (l *Logger) Fatal(message string) {
	l.entry.Fatal(message)
}

// Fatalf prints the log with a fatal format error message and stops the service instance
// WARNING: Only use for critical error messages that should prevent the service from running
func (l *Logger) Fatalf(message string, args ...interface{}) {
	l.entry.Fatalf(message, args...)
}

// Error prints the log at error level with given message
func (l *Logger) Error(message string) {
	l.entry.Error(message)
}

// ErrorWithFields prints the log at error level with given fields and message
func (l *Logger) ErrorWithFields(message string, fields logutils.Fields) {
	l.entry.WithFields(fields.ToMap()).Error(message)
}

// Errorf prints the log at error level with given formatted string
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.entry.Errorf(format, args...)
}

// Info prints the log at info level with given message
func (l *Logger) Info(message string) {
	l.entry.Info(message)
}

// InfoWithFields prints the log at info level with given fields and message
func (l *Logger) InfoWithFields(message string, fields logutils.Fields) {
	l.entry.WithFields(fields.ToMap()).Info(message)
}

// Infof prints the log at info level with given formatted string
func (l *Logger) Infof(format string, args ...interface{}) {
	l.entry.Infof(format, args...)
}

// Debug prints the log at debug level with given message
func (l *Logger) Debug(message string) {
	l.entry.Debug(message)
}

// DebugWithFields prints the log at debug level with given fields and message
func (l *Logger) DebugWithFields(message string, fields logutils.Fields) {
	l.entry.WithFields(fields.ToMap()).Debug(message)
}

// Debugf prints the log at debug level with given formatted string
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.entry.Debugf(format, args...)
}

// Warn prints the log at warn level with given message
func (l *Logger) Warn(message string) {
	l.entry.Warn(message)
}

// WarnWithFields prints the log at warn level with given fields and message
func (l *Logger) WarnWithFields(message string, fields logutils.Fields) {
	l.entry.WithFields(fields.ToMap()).Warn(message)
}

// Warnf prints the log at warn level with given formatted string
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.entry.Warnf(format, args...)
}
