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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/rokwire/rokwire-sdk-go/utils/errors"
	"github.com/rokwire/rokwire-sdk-go/utils/logging/logutils"
)

// RequestContext defines the context of an HTTP request to be logged
type RequestContext struct {
	Method     string
	Path       string
	Headers    map[string][]string
	PrevSpanID string
}

func (r RequestContext) String() string {
	return fmt.Sprintf("%s %s prev_span_id: %s headers: %v", r.Method, r.Path, r.PrevSpanID, r.Headers)
}

// Log struct defines a log object of a request
type Log struct {
	logger    *Logger
	traceID   string
	spanID    string
	request   RequestContext
	context   logutils.Fields
	layer     int
	suppress  bool
	hasLogged bool
}

// NewLog is a constructor for a log object
func (l *Logger) NewLog(traceID string, request RequestContext) *Log {
	if traceID == "" {
		traceID = uuid.New().String()
	}
	spanID := uuid.New().String()
	log := &Log{l, traceID, spanID, request, logutils.Fields{}, 0, false, false}
	return log
}

// NewRequestLog is a constructor for a log object for a request
func (l *Logger) NewRequestLog(r *http.Request) *Log {
	if r == nil {
		return &Log{logger: l}
	}

	traceID := r.Header.Get("trace-id")
	if traceID == "" {
		traceID = uuid.New().String()
	}

	prevSpanID := r.Header.Get("span-id")
	spanID := uuid.New().String()

	method := r.Method
	path := r.URL.Path

	headers := make(map[string][]string)
	for key, value := range r.Header {
		var logValue []string
		//do not log sensitive information
		if logutils.ContainsString(l.sensitiveHeaders, key) {
			logValue = append(logValue, "---")
		} else {
			logValue = value
		}
		headers[key] = logValue
	}

	request := RequestContext{Method: method, Path: path, Headers: headers, PrevSpanID: prevSpanID}

	suppress := false
	for _, props := range l.suppressRequests {
		if props.Match(r) {
			suppress = true
			break
		}
	}

	log := &Log{l, traceID, spanID, request, logutils.Fields{}, 0, suppress, false}
	return log
}

///////////////////////
///// Log Context /////
///////////////////////

// SetContext sets the provided context key to the provided value
func (l *Log) SetContext(fieldName string, value interface{}) {
	l.context[fieldName] = value
}

// AddContext adds any relevant unstructured data to context map
// If the provided key already exists in the context, an error is returned
func (l *Log) AddContext(fieldName string, value interface{}) error {
	if l == nil {
		return fmt.Errorf("error adding context: nil log")
	}

	if _, ok := l.context[fieldName]; ok {
		return fmt.Errorf("error adding context: %s already exists", fieldName)
	}

	l.context[fieldName] = value
	return nil
}

////////////////////////////
///// Request Handlers /////
////////////////////////////

// RequestReceived prints the request context of a log object
func (l *Log) RequestReceived() {
	if l == nil || l.logger == nil || l.suppress {
		return
	}

	fields := l.getRequestFields()
	fields["request"] = l.request
	l.logger.InfoWithFields("Request Received", fields)
}

// RequestComplete prints the context of a log object
func (l *Log) RequestComplete() {
	if l == nil || l.logger == nil {
		return
	}

	hasLogged := l.hasLogged
	fields := l.getRequestFields()

	if l.suppress {
		if hasLogged {
			fields["request"] = l.request
		} else {
			return
		}
	}

	fields["context"] = l.context
	l.logger.InfoWithFields("Request Complete", fields)
}

// getRequestFields() populates a map with all the fields of a request
//
//	layer: Number of function calls between caller and getRequestFields()
func (l *Log) getRequestFields() logutils.Fields {
	if l == nil {
		return logutils.Fields{}
	}

	l.hasLogged = true
	fields := logutils.Fields{"trace_id": l.traceID, "span_id": l.spanID, "function_name": getLogPrevFuncName(l.layer)}
	if l.suppress {
		fields["suppress"] = true
	}
	l.resetLayer()

	return fields
}

//////////////////////////
///// Header Helpers /////
//////////////////////////

// SetRequestHeaders sets the trace and span id headers for a request to another service
//
//	This function should always be called when making a request to another Rokwire service
func (l *Log) SetRequestHeaders(r *http.Request) {
	if l == nil || r == nil {
		return
	}

	r.Header.Set("trace-id", l.traceID)
	r.Header.Set("span-id", l.spanID)
}

// SetResponseHeaders sets the trace id header for a response
//
//	This function should always be called when returning a response
func (l *Log) SetResponseHeaders(r *HTTPResponse) {
	if l == nil || r == nil {
		return
	}

	r.Headers["trace-id"] = []string{l.traceID}
	r.Headers["span-id"] = []string{l.spanID}
}

/////////////////////////////////
///// HttpResponse Handlers /////
/////////////////////////////////

// SendHTTPResponse finalizes response data and sends the content of an HttpResponse to the provided http.ResponseWriter
//
//	Params:
//		w: The http response writer for the active request
//		response: The HttpResponse to be sent
func (l *Log) SendHTTPResponse(w http.ResponseWriter, response HTTPResponse) {
	for _, cookie := range response.Cookies {
		http.SetCookie(w, &cookie)
	}

	l.SetResponseHeaders(&response)
	for key, values := range response.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.ResponseCode)
	if len(response.Body) > 0 {
		w.Write(response.Body)
	}
}

// HTTPResponseSuccess generates an HttpResponse with the message "Success" with status code 200, sets standard headers, and stores the status to the log context
func (l *Log) HTTPResponseSuccess() HTTPResponse {
	return l.HTTPResponseSuccessMessage("Success")
}

// HTTPResponseSuccessMessage generates an HttpResponse with the provided success message with status code 200, sets standard headers, and stores the message and status to the log context
//
//	Params:
//		msg: The success message
func (l *Log) HTTPResponseSuccessMessage(message string) HTTPResponse {
	return l.HTTPResponseSuccessStatusMessage(message, http.StatusOK)
}

// HTTPResponseSuccessStatusMessage generates an HttpResponse with the provided success message and status code, sets standard headers, and stores the message and status to the log context
//
//	Params:
//		msg: The success message
//		code: The HTTP response code to be set
func (l *Log) HTTPResponseSuccessStatusMessage(message string, code int) HTTPResponse {
	l.SetContext("success", message)
	return l.HTTPResponseSuccessStatusBytes([]byte(message), "text/plain; charset=utf-8", code)
}

// HTTPResponseSuccessJSON generates an HttpResponse with the provided JSON as the HTTP response body with status code 200, sets standard headers,
// and stores the status to the log context
//
//	Params:
//		json: JSON encoded response data
func (l *Log) HTTPResponseSuccessJSON(json []byte) HTTPResponse {
	return l.HTTPResponseSuccessStatusJSON(json, http.StatusOK)
}

// HTTPResponseSuccessStatusJSON generates an HttpResponse with the provided JSON as the HTTP response body and status code, sets standard headers,
// and stores the status to the log context
//
//	Params:
//		json: JSON encoded response data
//		code: The HTTP response code to be set
func (l *Log) HTTPResponseSuccessStatusJSON(json []byte, code int) HTTPResponse {
	return l.HTTPResponseSuccessStatusBytes(json, "application/json; charset=utf-8", code)
}

// HTTPResponseSuccessBytes generates an HttpResponse with the provided bytes as the HTTP response body with status code 200,
// sets standard headers, and stores the status to the log context
//
//	Params:
//		bytes: Response data
//		contentType: Content type header string
func (l *Log) HTTPResponseSuccessBytes(bytes []byte, contentType string) HTTPResponse {
	return l.HTTPResponseSuccessStatusBytes(bytes, contentType, http.StatusOK)
}

// HTTPResponseSuccessStatusBytes generates an HttpResponse with the provided bytes as the HTTP response body and status code,
// sets standard headers, and stores the status to the log context
//
//	Params:
//		bytes: Response data
//		contentType: Content type header string
//		code: The HTTP response code to be set
func (l *Log) HTTPResponseSuccessStatusBytes(bytes []byte, contentType string, code int) HTTPResponse {
	l.SetContext("status_code", code)

	headers := map[string][]string{}
	headers["Content-Type"] = []string{contentType}
	headers["X-Content-Type-Options"] = []string{"nosniff"}
	return HTTPResponse{ResponseCode: code, Headers: headers, Body: bytes}
}

// HTTPResponseSuccessAction generates an HttpResponse with the provided success action message with status code 200, sets standard headers, and stores the message to the log context
//
//	Params:
//		action: The action that is occurring
//		dataType: The data type that the action is occurring on
//		args: Any args that should be included in the message (nil if none)
func (l *Log) HTTPResponseSuccessAction(action logutils.MessageActionType, dataType logutils.MessageDataType, args logutils.MessageArgs) HTTPResponse {
	return l.HTTPResponseSuccessStatusAction(action, dataType, args, http.StatusOK)
}

// HTTPResponseSuccessStatusAction generates an HttpResponse with the provided success action message and status code, sets standard headers, and stores the message to the log context
//
//	Params:
//		action: The action that is occurring
//		dataType: The data type that the action is occurring on
//		args: Any args that should be included in the message (nil if none)
//		code: The HTTP response code to be set
func (l *Log) HTTPResponseSuccessStatusAction(action logutils.MessageActionType, dataType logutils.MessageDataType, args logutils.MessageArgs, code int) HTTPResponse {
	message := logutils.MessageAction(logutils.StatusSuccess, action, dataType, args)
	return l.HTTPResponseSuccessStatusMessage(message, code)
}

// HTTPResponseError logs the provided message and error and generates an HttpResponse
//
//	Params:
//		message: The error message
//		err: The error received from the application
//		code: The HTTP response code to be set
//		showDetails: Only provide 'message' not 'err' in HTTP response when false
func (l *Log) HTTPResponseError(message string, err error, code int, showDetails bool) HTTPResponse {
	l.addLayer(1)
	defer l.resetLayer()

	message = l.errorHelper(message, err, code, showDetails)
	return NewJSONErrorHTTPResponse(message, code)
}

// HTTPResponseErrorAction logs an action message and error and generates an HttpResponse
//
//	action: The action that is occurring
//	dataType: The data type
//	args: Any args that should be included in the message (nil if none)
//	err: The error received from the application
//	code: The HTTP response code to be set
//	showDetails: Only generated message not 'err' in HTTP response when false
func (l *Log) HTTPResponseErrorAction(action logutils.MessageActionType, dataType logutils.MessageDataType, args logutils.MessageArgs, err error, code int, showDetails bool) HTTPResponse {
	message := logutils.MessageAction(logutils.StatusError, action, dataType, args)

	l.addLayer(1)
	defer l.resetLayer()

	return l.HTTPResponseError(message, err, code, showDetails)
}

// HTTPResponseErrorData logs a data message and error and generates an HttpResponse
//
//	status: The status of the data
//	dataType: The data type
//	args: Any args that should be included in the message (nil if none)
//	err: The error received from the application
//	code: The HTTP response code to be set
//	showDetails: Only provide 'msg' not 'err' in HTTP response when false
func (l *Log) HTTPResponseErrorData(status logutils.MessageDataStatus, dataType logutils.MessageDataType, args logutils.MessageArgs, err error, code int, showDetails bool) HTTPResponse {
	message := logutils.MessageData(status, dataType, args)

	l.addLayer(1)
	defer l.resetLayer()

	return l.HTTPResponseError(message, err, code, showDetails)
}

func (l *Log) errorHelper(message string, err error, code int, showDetails bool) string {
	l.addLayer(1)
	defer l.resetLayer()

	l.SetContext("status_code", code)

	status := errors.Status(err)
	if len(status) == 0 {
		status = strings.ReplaceAll(strings.ToLower(http.StatusText(code)), " ", "-")
	}
	l.SetContext("status", status)

	detailMsg := l.LogError(message, err)
	if showDetails {
		message = detailMsg
	}

	response := map[string]string{"status": status, "message": message}
	jsonMessage, _ := json.Marshal(response)
	message = string(jsonMessage)
	return message
}

// LogError prints the log at error level with given message and error
//
//	Returns combined error message as string
func (l *Log) LogError(message string, err error) string {
	msg := fmt.Sprintf("%s: %s", message, errors.Root(err))
	if l == nil || l.logger == nil {
		return msg
	}

	requestFields := l.getRequestFields()
	if err != nil {
		requestFields["error"] = err.Error()
	}
	l.logger.withFields(requestFields).Error(message)
	return msg
}

/////////////////////////////
///// Log Layer Helpers /////
/////////////////////////////

func (l *Log) resetLayer() {
	l.layer = 0
}

func (l *Log) addLayer(layer int) {
	l.layer += layer
}

// getLogPrevFuncName - fetches the calling function name when logging
//
//	layer: Number of internal library function calls above caller
func getLogPrevFuncName(layer int) string {
	return logutils.GetFuncName(5 + layer)
}

//////////////////////
///// Log Levels /////
//////////////////////

// LogMessage logs and returns a Message at the designated level
//
//	level: The log level (Info, Debug, Warn, Error)
//	message: The message to log
func (l *Log) LogMessage(level LogLevel, message string) string {
	l.addLayer(1)

	switch level {
	case Debug:
		l.Debug(message)
	case Info:
		l.Info(message)
	case Warn:
		l.Warn(message)
	case Error:
		l.Error(message)
	default:
		l.resetLayer()
	}

	return message
}

// Info prints the log at info level with given message
func (l *Log) Info(message string) {
	if l == nil || l.logger == nil || l.suppress {
		return
	}

	requestFields := l.getRequestFields()
	l.logger.withFields(requestFields).Info(message)
}

// InfoWithDetails prints the log at info level with given fields and message
func (l *Log) InfoWithDetails(message string, details logutils.Fields) {
	if l == nil || l.logger == nil || l.suppress {
		return
	}

	requestFields := l.getRequestFields()
	requestFields["details"] = details
	l.logger.withFields(requestFields).Info(message)
}

// Infof prints the log at info level with given formatted string
func (l *Log) Infof(format string, args ...interface{}) {
	if l == nil || l.logger == nil || l.suppress {
		return
	}

	requestFields := l.getRequestFields()
	l.logger.withFields(requestFields).Infof(format, args...)
}

// Debug prints the log at debug level with given message
func (l *Log) Debug(message string) {
	if l == nil || l.logger == nil || l.suppress {
		return
	}

	requestFields := l.getRequestFields()
	l.logger.withFields(requestFields).Debug(message)
}

// DebugWithDetails prints the log at debug level with given fields and message
func (l *Log) DebugWithDetails(message string, details logutils.Fields) {
	if l == nil || l.logger == nil || l.suppress {
		return
	}

	requestFields := l.getRequestFields()
	requestFields["details"] = details
	l.logger.withFields(requestFields).Debug(message)
}

// Debugf prints the log at debug level with given formatted string
func (l *Log) Debugf(format string, args ...interface{}) {
	if l == nil || l.logger == nil || l.suppress {
		return
	}

	requestFields := l.getRequestFields()
	l.logger.withFields(requestFields).Debugf(format, args...)
}

// Warn prints the log at warn level with given message
func (l *Log) Warn(message string) {
	if l == nil || l.logger == nil {
		return
	}

	requestFields := l.getRequestFields()
	l.logger.withFields(requestFields).Warn(message)
}

// WarnWithDetails prints the log at warn level with given details and message
func (l *Log) WarnWithDetails(message string, details logutils.Fields) {
	if l == nil || l.logger == nil {
		return
	}

	requestFields := l.getRequestFields()
	requestFields["details"] = details
	l.logger.withFields(requestFields).Warn(message)
}

// Warnf prints the log at warn level with given formatted string
func (l *Log) Warnf(format string, args ...interface{}) {
	if l == nil || l.logger == nil {
		return
	}

	requestFields := l.getRequestFields()
	l.logger.withFields(requestFields).Warnf(format, args...)
}

// WarnError prints the log at warn level with given message and error
//
//	Returns error message as string
func (l *Log) WarnError(message string, err error) string {
	msg := fmt.Sprintf("%s: %s", message, errors.Root(err))
	if l == nil || l.logger == nil {
		return msg
	}

	requestFields := l.getRequestFields()
	if err != nil {
		requestFields["error"] = err.Error()
	}
	l.logger.withFields(requestFields).Warn(message)
	return msg
}

// Error prints the log at error level with given message
// Note: If possible, use LogError() instead
func (l *Log) Error(message string) {
	if l == nil || l.logger == nil {
		return
	}

	requestFields := l.getRequestFields()
	l.logger.withFields(requestFields).Error(message)
}

// ErrorWithDetails prints the log at error level with given details and message
func (l *Log) ErrorWithDetails(message string, details logutils.Fields) {
	if l == nil || l.logger == nil {
		return
	}

	requestFields := l.getRequestFields()
	requestFields["details"] = details
	l.logger.withFields(requestFields).Error(message)
}

// Errorf prints the log at error level with given formatted string
// Note: If possible, use LogError() instead
func (l *Log) Errorf(format string, args ...interface{}) {
	if l == nil || l.logger == nil {
		return
	}

	requestFields := l.getRequestFields()
	l.logger.withFields(requestFields).Errorf(format, args...)
}
