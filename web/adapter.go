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
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/common"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
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

	openapi3SectionServers string = "servers"
)

// Adapter entity
type Adapter struct {
	baseURL   string
	port      string
	serviceID string

	auth *Auth

	docsYAMLPath  string
	cachedYamlDoc []byte
	paths         map[string]*openapi3.PathItem

	apisHandler APIsHandler

	app *common.Application

	logger *logs.Logger
}

// Start starts the module
func (a *Adapter) Start() {

	router := mux.NewRouter().StrictSlash(true)

	// setup doc apis
	baseRouter := router.PathPrefix("/" + a.serviceID).Subrouter()
	baseRouter.PathPrefix("/doc/ui").Handler(a.serveDocUI())
	baseRouter.HandleFunc("/doc", a.serveDoc)

	err := a.routeAPIs(router)
	if err != nil {
		a.logger.Fatal(err.Error())
	}

	a.logger.Fatalf("Error serving: %v", http.ListenAndServe(":"+a.port, router))
}

// routeAPIs calls registerHandler for every path specified as auto-generated in docs
func (a *Adapter) routeAPIs(router *mux.Router) error {
	for path, pathItem := range a.paths {
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

	//TODO: setup configs endpoints

	return nil
}

func (a *Adapter) serveDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")

	if a.cachedYamlDoc != nil {
		http.ServeContent(w, r, "", time.Now(), bytes.NewReader([]byte(a.cachedYamlDoc)))
	} else {
		http.ServeFile(w, r, a.docsYAMLPath)
	}
}

func (a *Adapter) serveDocUI() http.Handler {
	url := fmt.Sprintf("%s/doc", a.baseURL)
	return httpSwagger.Handler(httpSwagger.URL(url))
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(port string, serviceID string, app *common.Application, docsYAMLPath string, baseServerURL string, prodServerURL string,
	testServerURL string, devServerURL string, serviceRegManager *auth.ServiceRegManager, logger *logs.Logger) Adapter {
	//openAPI doc
	loader := &openapi3.Loader{Context: context.Background(), IsExternalRefsAllowed: true}

	yamlDoc, err := os.ReadFile(docsYAMLPath)
	if err != nil {
		logger.Fatalf("error reading docs file - %s", err.Error())
	}

	doc, err := loader.LoadFromData(yamlDoc)
	if err != nil {
		logger.Fatalf("error loading docs yaml - %s", err.Error())
	}

	yamlBaseDoc, err := os.ReadFile("./web/docs/gen/def.yaml")
	if err != nil {
		logger.Fatalf("error reading base docs file - %s", err.Error())
	}

	baseDoc, err := loader.LoadFromData(yamlBaseDoc)
	if err != nil {
		logger.Fatalf("error loading base docs yaml - %s", err.Error())
	}

	err = mergeDocsYAML(doc, baseDoc, serviceID, baseServerURL, prodServerURL, testServerURL, devServerURL)
	if err != nil {
		logger.Fatalf("error merging api docs - %s", err.Error())
	}

	err = doc.Validate(loader.Context, openapi3.EnableExamplesValidation())
	if err != nil {
		logger.Fatalf("error on openapi3 validate - %s", err.Error())
	}

	//To correctly route traffic to base path, we must add to all paths since servers are ignored
	paths := make(map[string]*openapi3.PathItem, doc.Paths.Len())
	for path, obj := range doc.Paths.Map() {
		paths["/"+serviceID+path] = obj
	}

	auth, err := NewAuth(serviceRegManager)
	if err != nil {
		logger.Fatalf("error creating auth - %s", err.Error())
	}

	apisHandler := NewAPIsHandler(app)
	return Adapter{baseURL: baseServerURL, port: port, serviceID: serviceID, cachedYamlDoc: yamlDoc, docsYAMLPath: docsYAMLPath,
		auth: auth, paths: paths, apisHandler: apisHandler, app: app, logger: logger}
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
	configDataSchemas := make([]*openapi3.SchemaRef, 0)
	for key, schema := range baseDoc.Components.Schemas {
		if doc.Components.Schemas[key] == nil {
			if strings.Contains(key, "ConfigData") {
				configDataSchemas = append(configDataSchemas, schema)
			}
			doc.Components.Schemas[key] = schema
		}
	}

	configSchema := doc.Components.Schemas["Config"]
	if configSchema != nil {
		configDataSchema := configSchema.Value.Properties["data"]
		if configDataSchema != nil {
			anyOf := make(openapi3.SchemaRefs, 0)
			for _, configDataSchema := range configDataSchemas {
				anyOf = append(anyOf, configDataSchema)
			}
			configDataSchema.Value = &openapi3.Schema{AnyOf: anyOf}
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
