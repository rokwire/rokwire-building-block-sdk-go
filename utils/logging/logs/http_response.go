// Copyright 2022 Board of Trustees of the University of Illinois
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

package logs

import "net/http"

// HTTPResponse is an entity which contains the data to be sent in an HTTP response
type HTTPResponse struct {
	ResponseCode int
	Headers      map[string][]string
	Body         []byte
	Cookies      []http.Cookie
}

// SetCookie appends the given cookie to the list of cookies in the response
func (h *HTTPResponse) SetCookie(cookie http.Cookie) {
	if h.Cookies == nil {
		h.Cookies = make([]http.Cookie, 0)
	}
	h.Cookies = append(h.Cookies, cookie)
}

// NewHTTPResponse generates an HTTPResponse with the provided data
func NewHTTPResponse(body []byte, headers map[string]string, code int) HTTPResponse {
	preparedHeaders := make(map[string][]string, len(headers))
	for key, value := range headers {
		preparedHeaders[key] = []string{value}
	}

	return HTTPResponse{ResponseCode: code, Headers: preparedHeaders, Body: body}
}

// NewErrorHTTPResponse generates an HTTPResponse with the correct headers for an error string
func NewErrorHTTPResponse(body string, code int) HTTPResponse {
	headers := map[string][]string{}
	headers["Content-Type"] = []string{"text/plain; charset=utf-8"}
	headers["X-Content-Type-Options"] = []string{"nosniff"}

	return HTTPResponse{ResponseCode: code, Headers: headers, Body: []byte(body)}
}

// NewJSONErrorHTTPResponse generates an HTTPResponse with the correct headers for a JSON encoded error
func NewJSONErrorHTTPResponse(body string, code int) HTTPResponse {
	headers := map[string][]string{}
	headers["Content-Type"] = []string{"application/json; charset=utf-8"}
	headers["X-Content-Type-Options"] = []string{"nosniff"}

	return HTTPResponse{ResponseCode: code, Headers: headers, Body: []byte(body)}
}
