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

package notifications

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

// NotificationAdapter contains configurations and helper functions required to utilize certain core services
type NotificationAdapter struct {
	serviceAccountManager *auth.ServiceAccountManager

	notificationsBaseURL string

	logger *logs.Logger
}

// NotificationMessage wrapper for internal message
type NotificationMessage struct {
	ID         *string                 `json:"id" bson:"id"` //optional
	OrgID      string                  `json:"org_id" bson:"org_id"`
	AppID      string                  `json:"app_id" bson:"app_id"`
	Priority   int                     `json:"priority" bson:"priority"`
	Recipients []NotificationRecipient `json:"recipients" bson:"recipients"`
	//Topic      *string                 `json:"topic" bson:"topic"`
	Subject string              `json:"subject" bson:"subject"`
	Sender  *NotificationSender `json:"sender,omitempty" bson:"sender,omitempty"`
	Body    string              `json:"body" bson:"body"`
	Time    *int64              `json:"time,omitempty"`
	Data    map[string]string   `json:"data" bson:"data"`
}

// NotificationRecipient recipients wrapper struct
type NotificationRecipient struct {
	UserID string `json:"user_id"`
	Name   string `json:"name"`
}

// NotificationSender notification sender
type NotificationSender struct {
	Type string       `json:"type" bson:"type"` // user or system
	User *CoreUserRef `json:"user,omitempty" bson:"user,omitempty"`
}

// CoreUserRef user reference that contains ExternalID & Name
type CoreUserRef struct {
	UserID *string `json:"user_id" bson:"user_id"`
	Name   *string `json:"name" bson:"name"`
}

// MessageRef wrapped message response from the Notifications BB
type MessageRef struct {
	OrgID string `json:"org_id" bson:"org_id"`
	AppID string `json:"app_id" bson:"app_id"`
	ID    string `json:"id" bson:"_id"`
}

// SendNotification sends notifications to a user
func (na *NotificationAdapter) SendNotification(logs *logs.Logger, notification NotificationMessage) (*MessageRef, error) {
	results, err := na.SendNotifications(logs, []NotificationMessage{notification})
	if err != nil {
		return nil, err
	}

	if len(results) > 0 {
		return &results[0], err
	}

	return nil, err
}

// SendNotifications sends notifications to a user
func (na *NotificationAdapter) SendNotifications(logs *logs.Logger, notifications []NotificationMessage) ([]MessageRef, error) {
	if len(notifications) > 0 {
		//for now
		message1 := notifications[0]
		appID := message1.AppID
		orgID := message1.OrgID

		url := fmt.Sprintf("%s/api/bbs/messages", na.notificationsBaseURL)

		bodyBytes, err := json.Marshal(notifications)
		if err != nil {
			logs.Errorf("SendNotification::error creating notification request - %s", err)
			return nil, err
		}

		req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
		if err != nil {
			logs.Errorf("SendNotification:error creating load user data request - %s", err)
			return nil, err
		}

		resp, err := na.serviceAccountManager.MakeRequest(req, appID, orgID)
		if err != nil {
			logs.Errorf("SendNotification: error sending request - %s", err)
			return nil, err
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			errorResponse, _ := ioutil.ReadAll(resp.Body)
			if errorResponse != nil {
				logs.Errorf("SendNotification: error with response code - %s", errorResponse)
			}
			logs.Errorf("SendNotification: error with response code - %d", resp.StatusCode)
			return nil, fmt.Errorf("SendNotification:error with response code != 200")
		}
		var notificationResponse []MessageRef
		err = json.NewDecoder(resp.Body).Decode(&notificationResponse)
		if err != nil {
			logs.Errorf("SendNotification: error with response code - %d", resp.StatusCode)
			return nil, fmt.Errorf("SendNotification: %s", err)
		}
		return notificationResponse, nil
	}

	return nil, nil
}

// SendMail sends email to a user
func (na *NotificationAdapter) SendMail(toEmail string, subject string, body string) error {
	return na.sendMail(toEmail, subject, body)
}

func (na *NotificationAdapter) sendMail(toEmail string, subject string, body string) error {
	if len(toEmail) > 0 && len(subject) > 0 && len(body) > 0 {
		url := fmt.Sprintf("%s/api/bbs/mail", na.notificationsBaseURL)

		bodyData := map[string]interface{}{
			"to_mail": toEmail,
			"subject": subject,
			"body":    body,
		}
		bodyBytes, err := json.Marshal(bodyData)
		if err != nil {
			log.Printf("sendMail error creating notification request - %s", err)
			return err
		}

		req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBytes))
		if err != nil {
			log.Printf("sendMail error creating load user data request - %s", err)
			return err
		}

		resp, err := na.serviceAccountManager.MakeRequest(req, "all", "all")
		if err != nil {
			log.Printf("sendMail: error sending request - %s", err)
			return err
		}

		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			responseData, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("sendMail error: unable to read response json: %s", err)
				return fmt.Errorf("sendMail error: unable to parse response json: %s", err)
			}
			if responseData != nil {
				log.Printf("sendMail rror with response code - %d, response: %s", resp.StatusCode, responseData)
			} else {
				log.Printf("sendMail rror with response code - %d", resp.StatusCode)
			}
			return fmt.Errorf("sendMail error with response code != 200")
		}
	}
	return nil
}

// NewNotificationsService creates and configures a new Service instance
func NewNotificationsService(serviceAccountManager *auth.ServiceAccountManager, notificationsBaseURL string, logger *logs.Logger) (*NotificationAdapter, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	if notificationsBaseURL == "" {
		return nil, errors.New("notifications base url is missing")
	}

	groups := NotificationAdapter{serviceAccountManager: serviceAccountManager, notificationsBaseURL: notificationsBaseURL, logger: logger}

	return &groups, nil
}
