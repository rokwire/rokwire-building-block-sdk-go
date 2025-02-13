// Copyright 2022 Board of Trustees of the University of Illinois.
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

package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/common"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/tokenauth"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/webauth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/errors"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

const (
	// xCoreFunction defines the core function from docs
	xCoreFunction string = "x-core-function"
	// xDataType defines the data type from docs
	xDataType string = "x-data-type"
	// xAuthType defines the auth type from docs
	xAuthType string = "x-authentication-type"
	// xConversionFunction defines the conversion function from docs
	xConversionFunction string = "x-conversion-function"
)

var (
	_, b, _, _ = runtime.Caller(0)
	basepath   = filepath.Dir(b)
)

// AdapterConfig is an object used to configure an Adapter
type AdapterConfig struct {
	// server URLs
	BaseServerURL string
	ProdServerURL string
	TestServerURL string
	DevServerURL  string

	// API docs path
	DocsYAMLPath string

	// auth policy paths
	ClientAuthPermissionPolicyPath string
	ClientAuthScopePolicyPath      string
	AdminAuthPermissionPolicyPath  string
	BBsAuthPermissionPolicyPath    string
	TPSAuthPermissionPolicyPath    string
	SystemAuthPermissionPolicyPath string
}

// Adapter entity
type Adapter[T common.Storage] struct {
	baseURL   string
	port      string
	serviceID string

	Auth *Auth

	docsYAMLPath  string
	cachedJSONDoc []byte
	Paths         map[string]*openapi3.PathItem

	apisHandler APIsHandler[T]

	// CORS policy
	corsAllowedOrigins []string
	corsAllowedHeaders []string

	Logger *logs.Logger

	// handler registration functions

	// registers auto-generated API handlers
	RegisterGeneratedHandlerFunc func(*mux.Router, string, string, string, string, string, interface{}, interface{}, interface{}) error
	// registers any manually defined API handlers
	RegisterManualHandlerFunc func(*mux.Router) error
	// registers additional auth handlers used by the service and not defined in the SDK
	AuthHandlerGetter func(string, interface{}) (tokenauth.Handler, error)
	// registers additional core handlers used by the service and not defined in the SDK
	CoreHandlerGetter func(string, string) (interface{}, error)
	// registers additional conversion functions used by the service and not defined in the SDK
	ConversionFuncGetter func(interface{}) (interface{}, error)
}

// Start starts the module
func (a *Adapter[T]) Start() {

	router := mux.NewRouter().StrictSlash(true)

	// setup doc apis
	baseRouter := router.PathPrefix("/" + a.serviceID).Subrouter()
	baseRouter.PathPrefix("/doc/ui").Handler(a.serveDocUI())
	baseRouter.HandleFunc("/doc", a.serveDoc)

	err := a.routeAPIs(router)
	if err != nil {
		a.Logger.Fatal(err.Error())
	}

	if a.RegisterManualHandlerFunc != nil {
		err = a.RegisterManualHandlerFunc(baseRouter)
		if err != nil {
			a.Logger.Fatal(err.Error())
		}
	}

	var handler http.Handler = router
	if len(a.corsAllowedOrigins) > 0 {
		// all origins will be allowed if len(a.corsAllowedOrigins) == 0
		handler = webauth.SetupCORS(a.corsAllowedOrigins, a.corsAllowedHeaders, router)
	}
	a.Logger.Fatalf("Error serving: %v", http.ListenAndServe(":"+a.port, handler))
}

// routeAPIs calls registerHandler for every path specified as auto-generated in docs
func (a *Adapter[T]) routeAPIs(router *mux.Router) error {
	for path, pathItem := range a.Paths {
		operations := map[string]*openapi3.Operation{
			http.MethodGet:    pathItem.Get,
			http.MethodPost:   pathItem.Post,
			http.MethodPut:    pathItem.Put,
			http.MethodDelete: pathItem.Delete,
		}

		for method, operation := range operations {
			if operation == nil || operation.Extensions[xCoreFunction] == nil || operation.Extensions[xDataType] == nil {
				continue
			}

			var requestBody interface{}
			tag := operation.Tags[0]
			convFunc := operation.Extensions[xConversionFunction]
			if operation.RequestBody != nil {
				// allow a panic to occur if something goes wrong
				// the service should be stopped anyway and the stack trace is logged without needing to recover and import runtime/debug to get the stack trace
				requestBody = operation.RequestBody.Value.Content.Get("application/json").Schema.Ref
			}
			err := a.registerHandler(router, path, method, tag, operation.Extensions[xCoreFunction].(string), operation.Extensions[xDataType].(string),
				operation.Extensions[xAuthType], requestBody, convFunc)
			if err != nil {
				errArgs := logutils.FieldArgs(operation.Extensions)
				errArgs["method"] = method
				errArgs["tag"] = tag
				return errors.WrapErrorAction(logutils.ActionRegister, "api handler", &errArgs, err)
			}
		}
	}

	return nil
}

func (a *Adapter[T]) serveDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")

	if a.cachedJSONDoc != nil {
		http.ServeContent(w, r, "", time.Now(), bytes.NewReader([]byte(a.cachedJSONDoc)))
	} else {
		http.ServeFile(w, r, a.docsYAMLPath)
	}
}

func (a *Adapter[T]) serveDocUI() http.Handler {
	url := fmt.Sprintf("%s/doc", a.baseURL)
	return httpSwagger.Handler(httpSwagger.URL(url))
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter[T common.Storage](port string, serviceID string, app *common.Application[T], config AdapterConfig,
	serviceRegManager *auth.ServiceRegManager, corsAllowedOrigins []string, corsAllowedHeaders []string, logger *logs.Logger) Adapter[T] {
	//openAPI doc
	loader := &openapi3.Loader{Context: context.Background(), IsExternalRefsAllowed: true}

	yamlDoc, err := os.ReadFile(config.DocsYAMLPath)
	if err != nil {
		logger.Fatalf("error reading docs file - %s", err.Error())
	}

	doc, err := loader.LoadFromData(yamlDoc)
	if err != nil {
		logger.Fatalf("error loading docs yaml - %s", err.Error())
	}

	yamlBaseDoc, err := os.ReadFile(basepath + "/def.yaml")
	if err != nil {
		logger.Fatalf("error reading base docs file - %s", err.Error())
	}

	baseDoc, err := loader.LoadFromData(yamlBaseDoc)
	if err != nil {
		logger.Fatalf("error loading base docs yaml - %s", err.Error())
	}

	err = mergeDocsYAML(doc, baseDoc, serviceID, config.BaseServerURL, config.ProdServerURL, config.TestServerURL, config.DevServerURL)
	if err != nil {
		logger.Fatalf("error merging api docs - %s", err.Error())
	}

	err = doc.Validate(loader.Context, openapi3.EnableExamplesValidation())
	if err != nil {
		logger.Fatalf("error on openapi3 validate - %s", err.Error())
	}
	mergedYamlDoc, err := doc.MarshalJSON()
	if err != nil {
		logger.Fatalf("error on marshal merged yaml doc - %s", err.Error())
	}

	//To correctly route traffic to base path, we must add to all paths since servers are ignored
	paths := make(map[string]*openapi3.PathItem, doc.Paths.Len())
	for path, obj := range doc.Paths.Map() {
		paths["/"+serviceID+path] = obj
	}

	auth, err := NewAuth(serviceRegManager, config.ClientAuthPermissionPolicyPath, config.ClientAuthScopePolicyPath,
		config.AdminAuthPermissionPolicyPath, config.BBsAuthPermissionPolicyPath, config.TPSAuthPermissionPolicyPath, config.SystemAuthPermissionPolicyPath)
	if err != nil {
		logger.Fatalf("error creating auth - %s", err.Error())
	}

	apisHandler := NewAPIsHandler(app)
	return Adapter[T]{baseURL: config.BaseServerURL, port: port, serviceID: serviceID, cachedJSONDoc: mergedYamlDoc, docsYAMLPath: config.DocsYAMLPath,
		Auth: auth, Paths: paths, apisHandler: apisHandler, corsAllowedOrigins: corsAllowedOrigins, corsAllowedHeaders: corsAllowedHeaders, Logger: logger}
}

func mergeDocsYAML(doc *openapi3.T, baseDoc *openapi3.T, serviceID string, baseServerURL string, prodServerURL string, testServerURL string, devServerURL string) error {
	// set server base URL(s)
	if baseServerURL != "" {
		doc.Servers = []*openapi3.Server{{URL: baseServerURL}}
	} else {
		doc.Servers = []*openapi3.Server{}
		if prodServerURL != "" {
			doc.Servers = append(doc.Servers, &openapi3.Server{URL: prodServerURL, Description: "Production server"})
		}
		if testServerURL != "" {
			doc.Servers = append(doc.Servers, &openapi3.Server{URL: testServerURL, Description: "Test server"})
		}
		if devServerURL != "" {
			doc.Servers = append(doc.Servers, &openapi3.Server{URL: devServerURL, Description: "Development server"})
		}
		doc.Servers = append(doc.Servers, &openapi3.Server{URL: fmt.Sprintf("http://localhost/%s", serviceID), Description: "Local server"})
	}

	// add tags from base doc if needed
	addTags := make([]*openapi3.Tag, 0)
	for _, baseTag := range baseDoc.Tags {
		addBaseTag := true
		for _, tag := range doc.Tags {
			if strings.ToLower(tag.Name) == strings.ToLower(baseTag.Name) {
				addBaseTag = false
				break
			}
		}
		if addBaseTag {
			addTags = append(addTags, baseTag)
		}
	}
	doc.Tags = append(doc.Tags, addTags...)

	// add base doc paths
	for key, path := range baseDoc.Paths.Map() {
		if doc.Paths.Find(key) == nil {
			doc.Paths.Set(key, path)
		}
	}

	// add base doc component schemas
	for key, schema := range baseDoc.Components.Schemas {
		if doc.Components.Schemas[key] == nil {
			doc.Components.Schemas[key] = schema
		}
	}

	// set config data types
	configDataSchemas := make([]*openapi3.SchemaRef, 0)
	for key, schema := range doc.Components.Schemas {
		if strings.Contains(key, "ConfigData") {
			configDataSchemas = append(configDataSchemas, schema)
		}
	}

	for key, schema := range doc.Components.Schemas {
		if strings.Contains(strings.ToLower(key), "config") {
			configDataSchema := schema.Value.Properties["data"]
			if configDataSchema != nil {
				hasAdditionalProperties := configDataSchema.Value.AdditionalProperties.Has != nil && *configDataSchema.Value.AdditionalProperties.Has
				if hasAdditionalProperties {
					anyOf := make(openapi3.SchemaRefs, 0)
					for _, configDataSchema := range configDataSchemas {
						anyOf = append(anyOf, configDataSchema)
					}
					configDataSchema.Value = &openapi3.Schema{AnyOf: anyOf}
				}
			}
		}
	}

	// add base doc component security schemes
	for key, securityScheme := range baseDoc.Components.SecuritySchemes {
		if doc.Components.SecuritySchemes[key] == nil {
			doc.Components.SecuritySchemes[key] = securityScheme
		}
	}

	return nil
}
