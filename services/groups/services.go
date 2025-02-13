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

package groups

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/core/auth"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
)

// GroupAdapter contains configurations and helper functions required to utilize certain core services
type GroupAdapter struct {
	serviceAccountManager *auth.ServiceAccountManager

	groupsBaseURL string

	logger *logs.Logger
}

// GetGroupMembership wrapps the group title and group membership status of user
type GetGroupMembership struct {
	GroupID string `json:"group_id"`
	Title   string `json:"group_title"`
	Status  string `json:"status"`
}

// Group represents group entity
type Group struct {
	ID                  string   `json:"id" bson:"_id"`
	ClientID            string   `json:"client_id" bson:"client_id"`
	Category            string   `json:"category" bson:"category"` //one of the enums categories list
	Title               string   `json:"title" bson:"title"`
	Privacy             string   `json:"privacy" bson:"privacy"` //public or private
	HiddenForSearch     bool     `json:"hidden_for_search" bson:"hidden_for_search"`
	Description         *string  `json:"description" bson:"description"`
	ImageURL            *string  `json:"image_url" bson:"image_url"`
	WebURL              *string  `json:"web_url" bson:"web_url"`
	Tags                []string `json:"tags" bson:"tags"`
	MembershipQuestions []string `json:"membership_questions" bson:"membership_questions"`
	IsAbuse             *bool    `json:"is_abuse,omitempty" bson:"is_abuse,omitempty"`

	Settings   *GroupSettings         `json:"settings" bson:"settings"` // TODO: Remove the pointer once the backward support is not needed any more!
	Attributes map[string]interface{} `json:"attributes" bson:"attributes"`

	CurrentMember *GroupMembership `json:"current_member"` // this is indicative and it's not required for update APIs
	Members       []Member         `json:"members,omitempty" bson:"members,omitempty"`
	Stats         GroupStats       `json:"stats" bson:"stats"`

	DateCreated                  time.Time  `json:"date_created" bson:"date_created"`
	DateUpdated                  *time.Time `json:"date_updated" bson:"date_updated"`
	DateMembershipUpdated        *time.Time `json:"date_membership_updated" bson:"date_membership_updated"`
	DateManagedMembershipUpdated *time.Time `json:"date_managed_membership_updated" bson:"date_managed_membership_updated"`

	AuthmanEnabled             bool    `json:"authman_enabled" bson:"authman_enabled"`
	AuthmanGroup               *string `json:"authman_group" bson:"authman_group"`
	OnlyAdminsCanCreatePolls   bool    `json:"only_admins_can_create_polls" bson:"only_admins_can_create_polls"`
	CanJoinAutomatically       bool    `json:"can_join_automatically" bson:"can_join_automatically"`
	BlockNewMembershipRequests bool    `json:"block_new_membership_requests" bson:"block_new_membership_requests"`
	AttendanceGroup            bool    `json:"attendance_group" bson:"attendance_group"`

	ResearchOpen             bool                           `json:"research_open" bson:"research_open"`
	ResearchGroup            bool                           `json:"research_group" bson:"research_group"`
	ResearchConsentStatement string                         `json:"research_consent_statement" bson:"research_consent_statement"`
	ResearchConsentDetails   string                         `json:"research_consent_details" bson:"research_consent_details"`
	ResearchDescription      string                         `json:"research_description" bson:"research_description"`
	ResearchProfile          map[string]map[string][]string `json:"research_profile" bson:"research_profile"`

	SyncStartTime *time.Time `json:"sync_start_time" bson:"sync_start_time"`
	SyncEndTime   *time.Time `json:"sync_end_time" bson:"sync_end_time"`
} // @name Group

// GroupStats wraps group statistics aggregation result
type GroupStats struct {
	TotalCount      int `json:"total_count" bson:"total_count"` // pending and rejected are excluded
	AdminsCount     int `json:"admins_count" bson:"admins_count"`
	MemberCount     int `json:"member_count" bson:"member_count"`
	PendingCount    int `json:"pending_count" bson:"pending_count"`
	RejectedCount   int `json:"rejected_count" bson:"rejected_count"`
	AttendanceCount int `json:"attendance_count" bson:"attendance_count"`
} //@name GroupStats

// Member represents group member entity
type Member struct {
	ID            string         `json:"id" bson:"id"`
	UserID        string         `json:"user_id" bson:"user_id"`
	ExternalID    string         `json:"external_id" bson:"external_id"`
	Name          string         `json:"name" bson:"name"`
	NetID         string         `json:"net_id" bson:"net_id"`
	Email         string         `json:"email" bson:"email"`
	PhotoURL      string         `json:"photo_url" bson:"photo_url"`
	Status        string         `json:"status" bson:"status"` //pending, member, admin, rejected
	RejectReason  string         `json:"reject_reason" bson:"reject_reason"`
	MemberAnswers []MemberAnswer `json:"member_answers" bson:"member_answers"`

	DateCreated  time.Time  `json:"date_created" bson:"date_created"`
	DateUpdated  *time.Time `json:"date_updated" bson:"date_updated"`
	DateAttended *time.Time `json:"date_attended" bson:"date_attended"`
} //@name Member

// GroupSettings wraps group settings and flags as a separate unit
type GroupSettings struct {
	MemberInfoPreferences MemberInfoPreferences `json:"member_info_preferences" bson:"member_info_preferences"`
	PostPreferences       PostPreferences       `json:"post_preferences" bson:"post_preferences"`
} // @name GroupSettings

// MemberInfoPreferences wrap settings for the visible member information
type MemberInfoPreferences struct {
	AllowMemberInfo    bool `json:"allow_member_info" bson:"allow_member_info"`
	CanViewMemberNetID bool `json:"can_view_member_net_id" bson:"can_view_member_net_id"`
	CanViewMemberName  bool `json:"can_view_member_name" bson:"can_view_member_name"`
	CanViewMemberEmail bool `json:"can_view_member_email" bson:"can_view_member_email"`
	CanViewMemberPhone bool `json:"can_view_member_phone" bson:"can_view_member_phone"`
} // @name MemberInfoPreferences

// PostPreferences wraps post preferences
type PostPreferences struct {
	AllowSendPost                bool `json:"allow_send_post" bson:"allow_send_post"`
	CanSendPostToSpecificMembers bool `json:"can_send_post_to_specific_members" bson:"can_send_post_to_specific_members"`
	CanSendPostToAdmins          bool `json:"can_send_post_to_admins" bson:"can_send_post_to_admins"`
	CanSendPostToAll             bool `json:"can_send_post_to_all" bson:"can_send_post_to_all"`
	CanSendPostReplies           bool `json:"can_send_post_replies" bson:"can_send_post_replies"`
	CanSendPostReactions         bool `json:"can_send_post_reactions" bson:"can_send_post_reactions"`
	CanSendPostGroupMessages     bool `json:"can_send_post_group_messages" bson:"can_send_post_group_messages"`
} // @name PostPreferences

// GroupMembership represents the membership of a user to a given group
type GroupMembership struct {
	ID         string `json:"id" bson:"_id"`
	ClientID   string `json:"client_id" bson:"client_id"`
	GroupID    string `json:"group_id" bson:"group_id"`
	UserID     string `json:"user_id" bson:"user_id"`
	ExternalID string `json:"external_id" bson:"external_id"`
	Name       string `json:"name" bson:"name"`
	NetID      string `json:"net_id" bson:"net_id"`
	Email      string `json:"email" bson:"email"`
	PhotoURL   string `json:"photo_url" bson:"photo_url"`

	Status string `json:"status" bson:"status"` //admin, pending, member, rejected

	RejectReason  string         `json:"reject_reason" bson:"reject_reason"`
	MemberAnswers []MemberAnswer `json:"member_answers" bson:"member_answers"`
	SyncID        string         `json:"sync_id" bson:"sync_id"` //ID of sync that last updated this membership

	NotificationsPreferences NotificationsPreferences `json:"notifications_preferences" bson:"notifications_preferences"`

	DateCreated  time.Time  `json:"date_created" bson:"date_created"`
	DateUpdated  *time.Time `json:"date_updated" bson:"date_updated"`
	DateAttended *time.Time `json:"date_attended" bson:"date_attended"`
} //@name GroupMembership

// NotificationsPreferences overrides default notification preferences on group level
type NotificationsPreferences struct {
	OverridePreferences bool `json:"override_preferences" bson:"override_preferences"`
	AllMute             bool `json:"all_mute" bson:"all_mute"`
	InvitationsMuted    bool `json:"invitations_mute" bson:"invitations_mute"`
	PostsMuted          bool `json:"posts_mute" bson:"posts_mute"`
	EventsMuted         bool `json:"events_mute" bson:"events_mute"`
	PollsMuted          bool `json:"polls_mute" bson:"polls_mute"`
} // @name NotificationsPreferences

// MemberAnswer represents member answer entity
type MemberAnswer struct {
	Question string `json:"question" bson:"question"`
	Answer   string `json:"answer" bson:"answer"`
} //@name MemberAnswer

// GetGroupMemberships Get aggregated title of the group and status of the member
func (na *GroupAdapter) GetGroupMemberships(logs logs.Logger, userID string) ([]GetGroupMembership, error) {
	url := fmt.Sprintf("%s/api/bbs/groups/%s/memberships", na.groupsBaseURL, userID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logs.Errorf("GetGroupMembership:error creating load user data request - %s", err)
		return nil, err
	}

	resp, err := na.serviceAccountManager.MakeRequest(req, "all", "all")
	if err != nil {
		logs.Errorf("GetGroupMembership: error sending request - %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errorResponse, _ := ioutil.ReadAll(resp.Body)
		if errorResponse != nil {
			logs.Errorf("GetGroupMembership: error with response code - %s", errorResponse)
		}
		logs.Errorf("GetGroupMembership: error with response code - %d", resp.StatusCode)
		return nil, fmt.Errorf("GetGroupEventUsers:error with response code != 200")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("GetGroupMembership: unable to read json: %s", err)
		return nil, fmt.Errorf("GetGroupMembership: unable to parse json: %s", err)
	}

	var getGroupMemberships []GetGroupMembership
	err = json.Unmarshal(data, &getGroupMemberships)
	if err != nil {
		log.Printf("GetGroupMembership: unable to parse json: %s", err)
		return nil, fmt.Errorf("GetGroupMembership: unable to parse json: %s", err)
	}

	return getGroupMemberships, nil
}

// GetGroupMembershipsByGroupID Get group memebers by groupID
func (na *GroupAdapter) GetGroupMembershipsByGroupID(logs logs.Logger, groupID string) ([]string, error) {
	url := fmt.Sprintf("%s/api/bbs/groups/%s/group-memberships", na.groupsBaseURL, groupID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logs.Errorf("GetGroupMembershipsByGroupID:error creating load user data request - %s", err)
		return nil, err
	}

	resp, err := na.serviceAccountManager.MakeRequest(req, "all", "all")
	if err != nil {
		logs.Errorf("GetGroupMembershipsByGroupID: error sending request - %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errorResponse, _ := ioutil.ReadAll(resp.Body)
		if errorResponse != nil {
			logs.Errorf("GetGroupMembershipsByGroupID: error with response code - %s", errorResponse)
		}
		logs.Errorf("GetGroupMembershipsByGroupID: error with response code - %d", resp.StatusCode)
		return nil, fmt.Errorf("GetGroupMembershipsByGroupID:error with response code != 200")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("GetGroupMembershipsByGroupID: unable to read json: %s", err)
		return nil, fmt.Errorf("GetGroupMembershipsByGroupID: unable to parse json: %s", err)
	}

	var groupMembers []string
	err = json.Unmarshal(data, &groupMembers)
	if err != nil {
		log.Printf("GetGroupMembershipsByGroupID: unable to parse json: %s", err)
		return nil, fmt.Errorf("GetGroupMembershipsByGroupID: unable to parse json: %s", err)
	}

	return groupMembers, nil
}

// FindGroups finds groups by ids
func (na *GroupAdapter) FindGroups(logs logs.Logger, groupIDs []string) ([]Group, error) {
	idsParam := strings.Join(groupIDs, ",")
	url := fmt.Sprintf("%s/api/bbs/groups?group-ids=%s", na.groupsBaseURL, idsParam)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logs.Errorf("GetGroupsGroupIDs:error creating load user data request - %s", err)
		return nil, err
	}

	resp, err := na.serviceAccountManager.MakeRequest(req, "all", "all")
	if err != nil {
		logs.Errorf("GetGroupsGroupIDs: error sending request - %s", err)
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errorResponse, _ := ioutil.ReadAll(resp.Body)
		if errorResponse != nil {
			logs.Errorf("GetGroupsGroupIDs: error with response code - %s", errorResponse)
		}
		logs.Errorf("GetGroupsGroupIDsD: error with response code - %d", resp.StatusCode)
		return nil, fmt.Errorf("GetGroupsGroupIDs:error with response code != 200")
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("GetGroupsGroupIDs: unable to read json: %s", err)
		return nil, fmt.Errorf("GetGroupsGroupIDs: unable to parse json: %s", err)
	}

	var groups []Group
	err = json.Unmarshal(data, &groups)
	if err != nil {
		log.Printf("GetGroupsGroupIDs: unable to parse json: %s", err)
		return nil, fmt.Errorf("GetGroupsGroupIDs: unable to parse json: %s", err)
	}

	return groups, nil
}

// NewGroupsService creates and configures a new Service instance
func NewGroupsService(serviceAccountManager *auth.ServiceAccountManager, groupsBaseURL string, logger *logs.Logger) (*GroupAdapter, error) {
	if serviceAccountManager == nil {
		return nil, errors.New("service account manager is missing")
	}

	if groupsBaseURL == "" {
		return nil, errors.New("groups base url is missing")
	}

	groups := GroupAdapter{serviceAccountManager: serviceAccountManager, groupsBaseURL: groupsBaseURL, logger: logger}

	return &groups, nil
}
