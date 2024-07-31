// Copyright 2024 Board of Trustees of the University of Illinois.
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

package common_test

import (
	"testing"

	"github.com/rokwire/rokwire-building-block-sdk-go/services/common"
)

func Test_appDefault_GetVersion(t *testing.T) {
	tests := []struct {
		name string
		a    common.Default
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := tt.a.GetVersion(); got == nil || *got != tt.want {
				t.Errorf("appDefault.GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
