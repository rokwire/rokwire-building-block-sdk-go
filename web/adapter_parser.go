package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/tokenauth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/errors"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils"
)

const (
	openapi3FormatDateTime string = "date-time"
	openapi3FormatFloat    string = "float"
)

// APIHandler represents a set of objects and functions that are needed to respond to an incoming request
type APIHandler[A any, R any, S any] struct {
	authorization   tokenauth.Handler
	conversionFunc  func(*tokenauth.Claims, *R) (*S, error)
	messageDataType logutils.MessageDataType

	getHandler              func(*tokenauth.Claims, map[string]interface{}) (*A, error)
	getManyHandler          func(*tokenauth.Claims, map[string]interface{}) ([]A, error)
	getNoParamHandler       func(*tokenauth.Claims) (*A, error)
	getPublicHandler        func(map[string]interface{}) (*A, error)
	getPublicNoParamHandler func() (*A, error)

	saveHandler        func(*tokenauth.Claims, map[string]interface{}, *S) (*A, error)
	saveNoParamHandler func(*tokenauth.Claims, *S) (*A, error)

	deleteHandler func(*tokenauth.Claims, map[string]interface{}) error
}

type openapi3Type interface {
	string | int | float64 | bool | time.Time
}

// HandleRequest responds to an incoming request by logging it, performing authorization checks, and calling the registered handler function
func (h *APIHandler[A, R, S]) HandleRequest(paths map[string]*openapi3.PathItem, logger *logs.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		logObj := logger.NewRequestLog(req)
		logObj.RequestReceived()

		pathKey, err := mux.CurrentRoute(req).GetPathTemplate()
		if err != nil {
			logObj.SendHTTPResponse(w, logObj.HTTPResponseErrorAction(logutils.MessageActionType(logutils.Unimplemented), logutils.TypeRequest, nil, errors.Newf("Path not found"), http.StatusNotFound, true))
			return
		}
		path := paths[pathKey]
		if path == nil {
			logObj.SendHTTPResponse(w, logObj.HTTPResponseErrorAction(logutils.MessageActionType(logutils.Unimplemented), logutils.TypeRequest, nil, errors.Newf("Path not found"), http.StatusNotFound, true))
			return
		}

		var responseStatus int
		var claims *tokenauth.Claims
		if h.authorization != nil {
			responseStatus, claims, err = h.authorization.Check(req)
			if err != nil {
				logObj.SendHTTPResponse(w, logObj.HTTPResponseErrorAction(logutils.ActionValidate, logutils.TypeRequest, nil, err, responseStatus, true))
				return
			}

			if claims != nil {
				logObj.SetContext("account_id", claims.Subject)
			}
		}

		var response logs.HTTPResponse
		switch req.Method {
		case http.MethodGet:
			response = h.handle(req, claims, path.Get, logObj)
		case http.MethodPost:
			response = h.handle(req, claims, path.Post, logObj)
		case http.MethodPut:
			response = h.handle(req, claims, path.Put, logObj)
		case http.MethodDelete:
			response = h.handle(req, claims, path.Delete, logObj)
		default:
			response = logObj.HTTPResponseErrorData(logutils.StatusInvalid, "method", nil, nil, http.StatusMethodNotAllowed, true)
		}

		logObj.SendHTTPResponse(w, response)
		logObj.RequestComplete()
	}
}

// SetCoreHandler sets the correct function field in handler by the function prototype of coreFunc
func (h *APIHandler[A, R, S]) SetCoreHandler(coreFunc interface{}, method string, tag string, ref string) error {
	ok := false
	switch method {
	case http.MethodGet:
		h.getHandler, ok = coreFunc.(func(*tokenauth.Claims, map[string]interface{}) (*A, error))
		if !ok {
			h.getManyHandler, ok = coreFunc.(func(*tokenauth.Claims, map[string]interface{}) ([]A, error))
		}
		if !ok {
			h.getNoParamHandler, ok = coreFunc.(func(*tokenauth.Claims) (*A, error))
		}
		if !ok {
			h.getPublicHandler, ok = coreFunc.(func(map[string]interface{}) (*A, error))
		}
		if !ok {
			h.getPublicNoParamHandler, ok = coreFunc.(func() (*A, error))
		}
	case http.MethodPost, http.MethodPut:
		h.saveHandler, ok = coreFunc.(func(*tokenauth.Claims, map[string]interface{}, *S) (*A, error))
		if !ok {
			h.saveNoParamHandler, ok = coreFunc.(func(*tokenauth.Claims, *S) (*A, error))
		}
	case http.MethodDelete:
		h.deleteHandler, ok = coreFunc.(func(*tokenauth.Claims, map[string]interface{}) error)
	}
	if !ok {
		return errors.ErrorData(logutils.StatusInvalid, "core function", &logutils.FieldArgs{"name": tag + "." + ref, "method": method})
	}

	return nil
}

/* Replaces api_ file functions by parsing parameters and request body
*  and calling the core function
*  The obj pointer represent the defined model for the request body or response
 */
func (h *APIHandler[A, R, S]) handle(r *http.Request, claims *tokenauth.Claims, operation *openapi3.Operation, l *logs.Log) logs.HTTPResponse {
	paramMap, response := getParams(l, r, operation.Parameters)
	if response != nil {
		return *response
	}

	var data *S
	var err error
	if operation.RequestBody != nil {
		if h.conversionFunc != nil {
			var requestBody R
			err = json.NewDecoder(r.Body).Decode(&requestBody)
			if err != nil {
				return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, true)
			}

			data, err = h.conversionFunc(claims, &requestBody)
			if err != nil {
				return l.HTTPResponseErrorAction(logutils.ActionParse, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, true)
			}
		} else {
			var dataVal S
			err = json.NewDecoder(r.Body).Decode(&dataVal)
			if err != nil {
				return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, true)
			}

			data = &dataVal
		}
	}

	var obj interface{}
	var actionType logutils.MessageActionType
	switch r.Method {
	case http.MethodGet:
		actionType = logutils.ActionGet
		if h.getManyHandler != nil {
			obj, err = h.getManyHandler(claims, paramMap)
		} else if h.getHandler != nil {
			obj, err = h.getHandler(claims, paramMap)
		} else if h.getNoParamHandler != nil {
			obj, err = h.getNoParamHandler(claims)
		} else if h.getPublicHandler != nil {
			obj, err = h.getPublicHandler(paramMap)
		} else if h.getPublicNoParamHandler != nil {
			obj, err = h.getPublicNoParamHandler()
		}
	case http.MethodPost, http.MethodPut:
		actionType = logutils.ActionSave
		if h.saveHandler != nil {
			obj, err = h.saveHandler(claims, paramMap, data)
		} else if h.saveNoParamHandler != nil {
			obj, err = h.saveNoParamHandler(claims, data)
		}
	case http.MethodDelete:
		actionType = logutils.ActionDelete
		if h.deleteHandler != nil {
			err = h.deleteHandler(claims, paramMap)
		}
	default:
		err = errors.ErrorData(logutils.StatusMissing, "api handler", &logutils.FieldArgs{"public": claims == nil})
		return l.HTTPResponseErrorAction(actionType, h.messageDataType, nil, err, http.StatusInternalServerError, false)
	}

	if err != nil {
		return l.HTTPResponseErrorAction(actionType, h.messageDataType, nil, err, http.StatusInternalServerError, true)
	}
	if (obj == (*A)(nil) || obj == nil) && r.Method != http.MethodGet {
		return l.HTTPResponseSuccess()
	}
	if objStr, ok := obj.(*string); ok {
		// avoids returning strings with unnecessary quotations
		return l.HTTPResponseSuccessMessage(*objStr)
	}

	responseData, err := json.Marshal(obj)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, logutils.TypeResponseBody, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(responseData)
}

// NewAPIHandler creates a new APIHandler object
func NewAPIHandler[A any, R any, S any](authorization tokenauth.Handler,
	conversionFunc func(*tokenauth.Claims, *R) (*S, error), messageDataType logutils.MessageDataType) APIHandler[A, R, S] {
	return APIHandler[A, R, S]{authorization: authorization, conversionFunc: conversionFunc, messageDataType: messageDataType}
}

/*
Returns map of all parameters from request with a response returning nil for success
- Required parameters are set as values
- Non-required parameters set as pointers
*/
func getParams(l *logs.Log, r *http.Request, params openapi3.Parameters) (map[string]interface{}, *logs.HTTPResponse) {
	paramMap := make(map[string]interface{})
	var response *logs.HTTPResponse
	for _, param := range params {
		if param == nil || param.Value == nil || param.Value.Schema == nil {
			continue
		}

		var values []string
		messageDataType := logutils.MessageDataType(logutils.TypeError)
		switch param.Value.In {
		case openapi3.ParameterInPath:
			values = []string{mux.Vars(r)[param.Value.Name]}
			messageDataType = logutils.TypePathParam
		case openapi3.ParameterInQuery:
			values = r.URL.Query()[param.Value.Name]
			messageDataType = logutils.TypeQueryParam
		}

		// Check if values are present
		if len(values) == 0 && param.Value.Required {
			resp := l.HTTPResponseErrorData(logutils.StatusMissing, messageDataType, logutils.StringArgs(param.Value.Name), nil, http.StatusBadRequest, true)
			return nil, &resp
		}

		// Parse value from schema
		value, err := getSchemaFromString(values, param.Value.Schema.Value, param.Value.Required)
		if err != nil {
			resp := l.HTTPResponseErrorAction(logutils.ActionParse, logutils.TypeArg, logutils.StringArgs(param.Value.Name), err, http.StatusBadRequest, true)
			return nil, &resp
		}

		paramMap[param.Value.Name] = value
	}

	return paramMap, response
}

// Recursively returns value of parsed string defined by schema
// - returns a pointer if not required
// - pointer is null if string is empty
// Note: Does not support recursive list types
func getSchemaFromString(strs []string, schema *openapi3.Schema, required bool) (interface{}, error) {
	if schema == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, "openapi3 schema", nil)
	}
	if schema.Type.Is(openapi3.TypeString) {
		if schema.Format == openapi3FormatDateTime {
			if required {
				return time.Parse(time.RFC3339, strs[0])
			} else if len(strs) > 0 {
				timeObj, err := time.Parse(time.RFC3339, strs[0])
				if err != nil {
					return nil, err
				}
				return &timeObj, nil
			}
			return (*time.Time)(nil), nil
		}
		if required {
			return strs[0], nil
		}
		if len(strs) > 0 {
			return &strs[0], nil
		}
		return (*string)(nil), nil
	} else if schema.Type.Is(openapi3.TypeInteger) {
		if required {
			return strconv.Atoi(strs[0])
		} else if len(strs) > 0 {
			intValue, err := strconv.Atoi(strs[0])
			if err != nil {
				return nil, err
			}
			return &intValue, nil
		}
		return (*int)(nil), nil
	} else if schema.Type.Is(openapi3.TypeNumber) {
		bitSize := 64
		if schema.Format == openapi3FormatFloat {
			bitSize = 32
		}
		if required {
			return strconv.ParseFloat(strs[0], bitSize)
		} else if len(strs) > 0 {
			floatValue, err := strconv.ParseFloat(strs[0], bitSize)
			if err != nil {
				return nil, err
			}
			return &floatValue, nil
		}
		return (*float64)(nil), nil
	} else if schema.Type.Is(openapi3.TypeBoolean) {
		if required {
			return strconv.ParseBool(strs[0])
		} else if len(strs) > 0 {
			boolValue, err := strconv.ParseBool(strs[0])
			if err != nil {
				return nil, err
			}
			return &boolValue, nil
		}
		return (*bool)(nil), nil
	} else if schema.Type.Is(openapi3.TypeArray) {
		if schema.Items == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, "schema items reference", nil)
		}
		itemsSchema := schema.Items.Value
		if itemsSchema == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, "schema items value", nil)
		}

		if itemsSchema.Type.Is(openapi3.TypeString) {
			if itemsSchema.Type.Is(openapi3FormatDateTime) {
				return parseArray[time.Time](strs, schema, required)
			}
			return parseArray[string](strs, schema, required)
		} else if itemsSchema.Type.Is(openapi3.TypeInteger) {
			return parseArray[int](strs, schema, required)
		} else if itemsSchema.Type.Is(openapi3.TypeNumber) {
			return parseArray[float64](strs, schema, required)
		} else if itemsSchema.Type.Is(openapi3.TypeBoolean) {
			return parseArray[bool](strs, schema, required)
		}
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, "schema type", logutils.StringArgs("parameter"))
}

/* Helper for recursively defining an array from a string
*  This is supposed to be recursive but is not due to
*  Go requiring arrays to have types defined beforehand
*  making it difficult to recursively define a type.
*  However, it should be possible some way.
 */
func parseArray[T openapi3Type](strs []string, schema *openapi3.Schema, required bool) (interface{}, error) {
	// Check if array has no items
	if len(strs) == 0 {
		if required {
			return nil, errors.ErrorData(logutils.StatusMissing, "array items", nil)
		}
		return (*[]T)(nil), nil
	}

	// Populate array
	values := make([]T, 0)
	for _, strValue := range strs {
		value, err := getSchemaFromString([]string{strValue}, schema.Items.Value, true)
		if err != nil {
			return nil, err
		}

		values = append(values, value.(T))
	}

	// If required return value. Else, return pointer
	if required {
		return values, nil
	}
	return &values, nil
}
