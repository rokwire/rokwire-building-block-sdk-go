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

package logutils

import (
	"fmt"
	"strings"
)

// Fields represents fields to be printed in a MessageDataType message
type Fields map[string]interface{}

// ToMap converts the fields to a standard map[string]interface{}
func (f Fields) ToMap() map[string]interface{} {
	return f
}

// MessageArgs is an interface for arguments to be included in a message
type MessageArgs interface {
	String() string
}

// FieldArgs are MessageArgs in the form of Fields
type FieldArgs Fields

func (f *FieldArgs) String() string {
	if f == nil {
		return ""
	}

	argMsg := ""
	for k, v := range *f {
		if argMsg != "" {
			argMsg += ", "
		}

		if v != nil {
			argMsg += fmt.Sprintf("%s=%v", k, v)
		} else {
			argMsg += k
		}
	}

	return argMsg
}

// ListArgs are MessageArgs in the form of a list
type ListArgs []string

func (l *ListArgs) String() string {
	if l == nil {
		return ""
	}

	return strings.Join(*l, ", ")
}

// StringArgs are MessageArgs in the form of a string
type StringArgs string

func (s StringArgs) String() string {
	return string(s)
}

// MessageDataStatus represent the status of the data in a DataMessage
type MessageDataStatus string

// MessageActionStatus represent the status of the action in an ActionMessage
type MessageActionStatus string

// MessageActionType represents the type that the action was performed on in an ActionMessage
type MessageActionType string

// MessageDataType represents the type of the data in a DataMessage
type MessageDataType string

const (
	//Errors

	// Unimplemented indicator
	Unimplemented string = "Unimplemented"

	//Types

	// StatusValid data status
	StatusValid MessageDataStatus = "Valid"
	// StatusInvalid data status
	StatusInvalid MessageDataStatus = "Invalid"
	// StatusFound data status
	StatusFound MessageDataStatus = "Found"
	// StatusMissing data status
	StatusMissing MessageDataStatus = "Missing"
	// StatusEnabled data status
	StatusEnabled MessageDataStatus = "Enabled"
	// StatusDisabled data status
	StatusDisabled MessageDataStatus = "Disabled"

	// StatusSuccess action status
	StatusSuccess MessageActionStatus = "Success"
	// StatusError action status
	StatusError MessageActionStatus = "Error"

	// Data

	// TypeArg data type
	TypeArg MessageDataType = "arg"
	// TypeTransaction data type
	TypeTransaction MessageDataType = "transaction"
	// TypeResult data type
	TypeResult MessageDataType = "result"

	// Primitives

	// TypeInt data type
	TypeInt MessageDataType = "int"
	// TypeUint data type
	TypeUint MessageDataType = "uint"
	// TypeFloat data type
	TypeFloat MessageDataType = "float"
	// TypeBool data type
	TypeBool MessageDataType = "bool"
	// TypeString data type
	TypeString MessageDataType = "string"
	// TypeByte data type
	TypeByte MessageDataType = "byte"
	// TypeError data type
	TypeError MessageDataType = "error"
	// TypeTime data type
	TypeTime MessageDataType = "time"

	// Requests

	// TypeRequest data type
	TypeRequest MessageDataType = "request"
	// TypeRequestBody data type
	TypeRequestBody MessageDataType = "request body"
	// TypeResponse data type
	TypeResponse MessageDataType = "response"
	// TypeResponseBody data type
	TypeResponseBody MessageDataType = "response body"
	// TypeQueryParam data type
	TypeQueryParam MessageDataType = "query param"
	// TypePathParam data type
	TypePathParam MessageDataType = "path param"
	// TypeHeader data type
	TypeHeader MessageDataType = "header"

	// Auth

	// TypeToken data type
	TypeToken MessageDataType = "token"
	// TypeClaims data type
	TypeClaims MessageDataType = "claims"
	// TypeClaim data type
	TypeClaim MessageDataType = "claim"
	// TypeScope data type
	TypeScope MessageDataType = "scope"
	// TypePermission data type
	TypePermission MessageDataType = "permission"

	// Actions

	// ActionInitialize action type
	ActionInitialize MessageActionType = "initializing"
	// ActionCompute action type
	ActionCompute MessageActionType = "computing"
	// ActionRegister action type
	ActionRegister MessageActionType = "registering"
	// ActionDeregister action type
	ActionDeregister MessageActionType = "deregistering"
	// ActionStart action type
	ActionStart MessageActionType = "starting"
	// ActionCommit action type
	ActionCommit MessageActionType = "committing"
	// ActionRefresh action type
	ActionRefresh MessageActionType = "refreshing"
	// ActionGenerate action type
	ActionGenerate MessageActionType = "generating"
	// ActionApply action type
	ActionApply MessageActionType = "applying"
	// ActionVerify action type
	ActionVerify MessageActionType = "verifying"
	// ActionPrepare action type
	ActionPrepare MessageActionType = "preparing"

	// Encryption Actions

	// ActionEncrypt action type
	ActionEncrypt MessageActionType = "encrypting"
	// ActionDecrypt action type
	ActionDecrypt MessageActionType = "decrypting"

	// Request/Response Actions

	// ActionSend action type
	ActionSend MessageActionType = "sending"
	// ActionRead action type
	ActionRead MessageActionType = "reading"

	// Encode Actions

	// ActionParse action type
	ActionParse MessageActionType = "parsing"
	// ActionEncode action type
	ActionEncode MessageActionType = "encoding"
	// ActionDecode action type
	ActionDecode MessageActionType = "decoding"

	// Marshal Actions

	// ActionMarshal action type
	ActionMarshal MessageActionType = "marshalling"
	// ActionUnmarshal action type
	ActionUnmarshal MessageActionType = "unmarshalling"
	// ActionValidate action type
	ActionValidate MessageActionType = "validating"
	// ActionCast action type
	ActionCast MessageActionType = "casting to"

	// Cache Actions

	// ActionCache action type
	ActionCache MessageActionType = "caching"
	// ActionLoadCache action type
	ActionLoadCache MessageActionType = "loading cached"

	// Auth Actions

	// ActionGrant action type
	ActionGrant MessageActionType = "granting"
	// ActionRevoke action type
	ActionRevoke MessageActionType = "revoking"

	// Operation Actions

	// ActionGet action type
	ActionGet MessageActionType = "getting"
	// ActionCreate action type
	ActionCreate MessageActionType = "creating"
	// ActionUpdate action type
	ActionUpdate MessageActionType = "updating"
	// ActionDelete action type
	ActionDelete MessageActionType = "deleting"

	// Storage Actions

	// ActionLoad action type
	ActionLoad MessageActionType = "loading"
	// ActionFind action type
	ActionFind MessageActionType = "finding"
	// ActionInsert action type
	ActionInsert MessageActionType = "inserting"
	// ActionReplace action type
	ActionReplace MessageActionType = "replacing"
	// ActionSave action type
	ActionSave MessageActionType = "saving"
	// ActionCount action type
	ActionCount MessageActionType = "counting"
)
