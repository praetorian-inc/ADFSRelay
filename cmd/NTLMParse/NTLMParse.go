// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/base64"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/praetorian-in/ADFSRelay/pkg/ntlm"
)

func main() {
	var input string
	fmt.Scanln(&input)

	decodedString, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		fmt.Println("Unable to decode base64 string, err: ", err)
		return
	}

	rawBytes := []byte(decodedString)
	ntlmMessage, err := ntlm.DecodeMessage(rawBytes)
	if err != nil {
		fmt.Println("Input is not a valid NTLM message, err: ", err)
		return
	}

	switch v := ntlmMessage.(type) {
	case *ntlm.NEGOTIATE_MESSAGE:
		spew.Dump(*v)
	case *ntlm.CHALLENGE_MESSAGE:
		spew.Dump(*v)
	case *ntlm.AUTHENTICATE_MESSAGE:
		spew.Dump(*v)
	}
}
