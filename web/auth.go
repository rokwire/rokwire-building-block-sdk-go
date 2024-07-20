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
	"net/http"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/authorization"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/errors"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/tokenauth"
)

// Auth handler
type Auth struct {
	Client tokenauth.Handlers
	Admin  tokenauth.Handlers
	BBs    tokenauth.Handlers
	TPS    tokenauth.Handlers
	System tokenauth.Handlers
}

// NewAuth creates new auth handler
func NewAuth(serviceRegManager *auth.ServiceRegManager, clientAuthPermissionPolicyPath string, clientAuthScopePolicyPath string,
	adminAuthPermissionPolicyPath string, bbsAuthPermissionPolicyPath string, tpsAuthPermissionPolicyPath string, systemAuthPermissionPolicyPath string) (*Auth, error) {
	client, err := newClientAuth(serviceRegManager, clientAuthPermissionPolicyPath, clientAuthScopePolicyPath)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "client auth", nil, err)
	}
	clientHandlers := tokenauth.NewHandlers(client)

	admin, err := newAdminAuth(serviceRegManager, adminAuthPermissionPolicyPath)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "admin auth", nil, err)
	}
	adminHandlers := tokenauth.NewHandlers(admin)

	bbs, err := newBBsAuth(serviceRegManager, bbsAuthPermissionPolicyPath)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "bbs auth", nil, err)
	}
	bbsHandlers := tokenauth.NewHandlers(bbs)

	tps, err := newTPSAuth(serviceRegManager, tpsAuthPermissionPolicyPath)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "tps auth", nil, err)
	}
	tpsHandlers := tokenauth.NewHandlers(tps)

	system, err := newSystemAuth(serviceRegManager, systemAuthPermissionPolicyPath)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "system auth", nil, err)
	}
	systemHandlers := tokenauth.NewHandlers(system)

	auth := Auth{
		Client: clientHandlers,
		Admin:  adminHandlers,
		BBs:    bbsHandlers,
		TPS:    tpsHandlers,
		System: systemHandlers,
	}
	return &auth, nil
}

///////

func newClientAuth(serviceRegManager *auth.ServiceRegManager, clientAuthPermissionPolicyPath string, clientAuthScopePolicyPath string) (*tokenauth.StandardHandler, error) {
	clientPermissionAuth := authorization.NewCasbinStringAuthorization(clientAuthPermissionPolicyPath)
	clientScopeAuth := authorization.NewCasbinScopeAuthorization(clientAuthScopePolicyPath, serviceRegManager.AuthService.ServiceID)
	clientTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, clientPermissionAuth, clientScopeAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "client token auth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if claims.Admin {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
		}
		if claims.System {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "system claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewScopeHandler(clientTokenAuth, check)
	return auth, nil
}

func newAdminAuth(serviceRegManager *auth.ServiceRegManager, adminAuthPermissionPolicyPath string) (*tokenauth.StandardHandler, error) {
	adminPermissionAuth := authorization.NewCasbinStringAuthorization(adminAuthPermissionPolicyPath)
	adminTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, adminPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "admin token auth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if !claims.Admin {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewStandardHandler(adminTokenAuth, check)
	return auth, nil
}

func newBBsAuth(serviceRegManager *auth.ServiceRegManager, bbsAuthPermissionPolicyPath string) (*tokenauth.StandardHandler, error) {
	bbsPermissionAuth := authorization.NewCasbinStringAuthorization(bbsAuthPermissionPolicyPath)
	bbsTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, bbsPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "bbs token auth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if !claims.Service {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "service claim", nil)
		}

		if !claims.FirstParty {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "first party claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewStandardHandler(bbsTokenAuth, check)
	return auth, nil
}

func newTPSAuth(serviceRegManager *auth.ServiceRegManager, tpsAuthPermissionPolicyPath string) (*tokenauth.StandardHandler, error) {
	tpsPermissionAuth := authorization.NewCasbinStringAuthorization(tpsAuthPermissionPolicyPath)
	tpsTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, tpsPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "tps token auth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if !claims.Service {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "service claim", nil)
		}

		if claims.FirstParty {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "first party claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewStandardHandler(tpsTokenAuth, check)
	return auth, nil
}

func newSystemAuth(serviceRegManager *auth.ServiceRegManager, systemAuthPermissionPolicyPath string) (*tokenauth.StandardHandler, error) {
	systemPermissionAuth := authorization.NewCasbinStringAuthorization(systemAuthPermissionPolicyPath)
	systemTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, systemPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "system token auth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if !claims.System {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "system claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewStandardHandler(systemTokenAuth, check)
	return auth, nil
}
