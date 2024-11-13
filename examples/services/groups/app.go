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

package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/rokwire/rokwire-building-block-sdk-go/internal/testutils"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/keys"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth/sigauth"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/groups"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/envloader"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

func main() {
	serviceID := "social" //put the service you would like to use
	logger := logs.NewLogger(serviceID, nil)
	envLoader := envloader.NewEnvLoader("dev", logger)

	serviceHost := envLoader.GetAndLogEnvVar("SDK_TESTER_BASE_URL", true, true)
	authHost := envLoader.GetAndLogEnvVar("SDK_TESTER_CORE_BB_BASE_URL", true, true)

	serviceAccountID := envLoader.GetAndLogEnvVar("SDK_TESTER_SERVICE_ACCOUNT_ID", true, true)

	staticToken := envLoader.GetAndLogEnvVar("SDK_TESTER_STATIC_TOKEN", false, true)

	privKey := envLoader.GetAndLogEnvVar("SDK_TESTER_SERVICE_PRIV_KEY", false, true)
	if len(privKey) == 0 {
		privKey = testutils.GetSampleRSAPrivKeyPem()
	}

	// Instantiate an auth.Service to maintain basic auth data
	authService := auth.Service{
		ServiceID:   serviceID,
		ServiceHost: serviceHost,
		FirstParty:  true,
		AuthBaseURL: authHost,
	}

	useSignatureAuth := true // change to false to use static token auth instead
	var serviceAccountLoader *auth.RemoteServiceAccountLoaderImpl

	// Instantiate a remote ServiceAccountLoader to load auth service account data from auth service
	if useSignatureAuth {
		// set up service registration manager and subscribe to auth service
		serviceRegLoader, err := auth.NewRemoteServiceRegLoader(&authService, []string{"auth"})
		if err != nil {
			logger.Fatalf("Error initializing remote service registration loader: %v", err)
		}

		serviceRegManager, err := auth.NewServiceRegManager(&authService, serviceRegLoader, !strings.HasPrefix(authService.ServiceHost, "http://localhost"))
		if err != nil {
			logger.Fatalf("Error initializing service registration manager: %v", err)
		}

		// parse private key
		privKeyRaw := strings.ReplaceAll(privKey, "\\n", "\n")
		privKey, err := keys.NewPrivKey(keys.PS256, privKeyRaw)
		if err != nil {
			logger.Fatalf("Error parsing priv key: %v", err)
		} else if serviceAccountID == "" {
			logger.Fatalf("Missing service account id")
		} else {
			// verify private key against service registration public key
			signatureAuth, err := sigauth.NewSignatureAuth(privKey, serviceRegManager, false, false)
			if err != nil {
				logger.Fatalf("Error initializing signature auth: %v", err)
			}

			// set up service account loader using signature auth
			serviceAccountLoader, err = auth.NewRemoteServiceAccountLoader(&authService, serviceAccountID, signatureAuth)
			if err != nil {
				logger.Fatalf("Error initializing remote service account loader: %v", err)
			}
		}
	} else {
		// set up service account loader using static token auth
		var err error
		staticTokenAuth := auth.StaticTokenServiceAuth{ServiceToken: staticToken}
		serviceAccountLoader, err = auth.NewRemoteServiceAccountLoader(&authService, serviceAccountID, staticTokenAuth)
		if err != nil {
			logger.Fatalf("Error initializing remote service account loader: %v", err)
		}
	}

	// Instantiate a remote ServiceAccountManager to manage service account-related data
	serviceAccountManager, err := auth.NewServiceAccountManager(&authService, serviceAccountLoader)
	if err != nil {
		logger.Fatalf("Error initializing service account manager: %v", err)
	}

	//create the adapter
	groupsURL := envLoader.GetAndLogEnvVar("SDK_TESTER_GROUPS_URL", true, true)
	groupsAdapter, err := groups.NewGroupsService(serviceAccountManager, groupsURL, logger)
	if err != nil {
		log.Printf("Error initializing groups service: %v", err)
	}

	//test calls
	res, err := groupsAdapter.GetGroupMemberships(*logger, "ds")
	if err != nil {
		log.Printf("error getting group memberships: %v", err)
	}
	fmt.Println(res)

	res2, err := groupsAdapter.GetGroupMembershipsByGroupID(*logger, "b4d23705-0326-4b64-ae19-830a6ff09f04")
	if err != nil {
		log.Printf("error getting group memberships: %v", err)
	}
	fmt.Println(res2)

	var groupIDs = []string{"146cc93d-47dd-11ec-9416-0a58a9feac02", "38f70744-3e21-11ec-b9bd-60f81dc8eb7c"}
	res3, err := groupsAdapter.GetGroupsGroupIDs(*logger, groupIDs)
	if err != nil {
		log.Printf("error getting group memberships: %v", err)
	}
	fmt.Println(res3)
}
