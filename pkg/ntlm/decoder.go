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

package ntlm

import "fmt"

func decodeInt16LittleEndian(rawBytes []byte) (uint16, error) {
	if len(rawBytes) != 2 {
		return 0, fmt.Errorf("byte array must be two bytes")
	}

	return uint16(rawBytes[0]) | uint16(rawBytes[1])<<8, nil
}

func decodeInt32LittleEndian(rawBytes []byte) (uint32, error) {
	if len(rawBytes) != 4 {
		return 0, fmt.Errorf("byte array must be four bytes")
	}

	return uint32(rawBytes[0]) | uint32(rawBytes[1])<<8 | uint32(rawBytes[2])<<16 | uint32(rawBytes[3])<<24, nil
}
