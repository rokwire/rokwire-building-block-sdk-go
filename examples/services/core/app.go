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
	"log"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/groups"
	"github.com/rokwire/rokwire-building-block-sdk-go/services/notifications"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

func main() {
	// Instantiate an auth.Service to maintain basic auth data
	authService := auth.Service{
		ServiceID:            "example",
		ServiceHost:          "http://localhost",
		FirstParty:           true,
		AuthBaseURL:          "http://localhost:5050/core",
		GroupsBaseURL:        "http://localhost/gr",
		NotificationsBaseURL: "http://localhost/notifications",
	}

	// Instantiate a remote ServiceAccountLoader to load auth service account data from auth service
	staticTokenAuth := auth.StaticTokenServiceAuth{ServiceToken: "exampleToken"}
	accountID := "9f627704-a39f-442a-ab60-44e6fd3c5e9d"
	serviceAccountLoader, err := auth.NewRemoteServiceAccountLoader(&authService, accountID, staticTokenAuth)
	if err != nil {
		log.Fatalf("Error initializing remote service account loader: %v", err)
	}

	// Instantiate a remote ServiceAccountManager to manage service account-related data
	serviceAccountManager, err := auth.NewServiceAccountManager(&authService, serviceAccountLoader)
	if err != nil {
		log.Fatalf("Error initializing service account manager: %v", err)
	}
	logger := logs.NewLogger(authService.ServiceID, nil)
	groupsAdapter, err := groups.NewGroupsService(serviceAccountManager, authService.GroupsBaseURL, logger)
	if err != nil {
		log.Printf("Error initializing groups service: %v", err)
	}

	notificationsAdapter, err := notifications.NewNotificationsService(serviceAccountManager, authService.NotificationsBaseURL, logger)
	if err != nil {
		log.Printf("Error initializing notifications service: %v", err)
	}

	// Instantiate a CoreService to utilize certain core services, such as reading deleted account IDs
	deletedAccountsConfig := core.DeletedAccountsConfig{
		Callback: printDeletedAccountIDs,
	}

	coreService, err := core.NewService(serviceAccountManager, &deletedAccountsConfig, groupsAdapter, notificationsAdapter, logger)
	if err != nil {
		log.Printf("Error initializing core service: %v", err)
	}

	coreService.StartDeletedAccountsTimer()

}

func printDeletedAccountIDs(accountIDs []string) error {
	log.Printf("Deleted account IDs: %v\n", accountIDs)
	return nil
}
