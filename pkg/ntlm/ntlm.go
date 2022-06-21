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

import (
	"bytes"
	"fmt"
)

func DecodeMessage(rawBytes []byte) (interface{}, error) {
	if len(rawBytes) < 12 {
		return nil, fmt.Errorf("NTLM message too short header must be at least 12 bytes")
	}

	signature := rawBytes[:8]
	if !bytes.Equal(signature, NTLM_SIGNATURE[:]) {
		return nil, fmt.Errorf("NTLM signature mismatch")
	}

	messageType := rawBytes[8:12][0]
	switch messageType {
	case MESSAGE_TYPE_NEGOTIATE:
		return DecodeNegotiateMessage(rawBytes)
	case MESSAGE_TYPE_CHALLENGE:
		return DecodeChallengeMessage(rawBytes)
	case MESSAGE_TYPE_AUTHENTICATE:
		return DecodeAuthenticateMessage(rawBytes)
	default:
		return nil, fmt.Errorf("NTLM invalid message type specified")
	}
}

func DecodeNegotiateMessage(rawBytes []byte) (*NEGOTIATE_MESSAGE, error) {
	var NegotiateMessage NEGOTIATE_MESSAGE

	if len(rawBytes) < NTLM_MINIMUM_NEGOTIATE_SIZE {
		return nil, fmt.Errorf("NTLM message too short")
	}

	NegotiateMessage.Signature = rawBytes[:8]
	NegotiateMessage.MessageType = decodeInt32LittleEndian(rawBytes[8:12])
	NegotiateMessage.NegotiateFlags = decodeInt32LittleEndian(rawBytes[12:16])
	NegotiateMessage.DecodedNegotiateFlags = DecodeNegotiateFlags(NegotiateMessage.NegotiateFlags)
	NegotiateMessage.DomainNameFields.DomainNameLen = decodeInt16LittleEndian(rawBytes[16:18])
	NegotiateMessage.DomainNameFields.DomainNameMaxLen = decodeInt16LittleEndian(rawBytes[18:20])
	NegotiateMessage.DomainNameFields.DomainNameBufferOffset = decodeInt32LittleEndian(rawBytes[20:24])
	NegotiateMessage.WorkstationFields.WorkstationLen = decodeInt16LittleEndian(rawBytes[24:26])
	NegotiateMessage.WorkstationFields.WorkstationMaxLen = decodeInt16LittleEndian(rawBytes[26:28])
	NegotiateMessage.WorkstationFields.WorkstationBufferOffset = decodeInt32LittleEndian(rawBytes[28:32])

	if NegotiateMessage.DecodedNegotiateFlags.NTLM_NEGOTIATE_VERSION {
		if len(rawBytes) < 40 {
			return nil, fmt.Errorf("NTLM message too short")
		}

		NegotiateMessage.Version.ProductMajorVersion = rawBytes[32]
		NegotiateMessage.Version.ProductMinorVersion = rawBytes[33]
		NegotiateMessage.Version.ProductBuild = decodeInt16LittleEndian(rawBytes[34:36])
		NegotiateMessage.Version.Reserved = rawBytes[36:39]
		NegotiateMessage.Version.NTLMRevisionCurrent = rawBytes[39]
	}

	DomainNameFields := NegotiateMessage.DomainNameFields
	beginOffset := DomainNameFields.DomainNameBufferOffset
	endOffset := beginOffset + uint32(DomainNameFields.DomainNameLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("DomainName, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	NegotiateMessage.DomainNameFields.DomainName = rawBytes[beginOffset:endOffset]

	WorkstationFields := NegotiateMessage.WorkstationFields
	beginOffset = WorkstationFields.WorkstationBufferOffset
	endOffset = beginOffset + uint32(WorkstationFields.WorkstationLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("WorkstationFields, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	NegotiateMessage.WorkstationFields.WorkstationName = rawBytes[beginOffset:endOffset]

	return &NegotiateMessage, nil
}

func DecodeChallengeMessage(rawBytes []byte) (*CHALLENGE_MESSAGE, error) {
	var ChallengeMessage CHALLENGE_MESSAGE
	var err error

	if len(rawBytes) < NTLM_MINIMUM_CHALLENGE_SIZE {
		return nil, fmt.Errorf("buffer is too short for a challenge message")
	}

	ChallengeMessage.Signature = rawBytes[:8]
	ChallengeMessage.MessageType = decodeInt32LittleEndian(rawBytes[8:12])
	ChallengeMessage.TargetNameFields.TargetNameLen = decodeInt16LittleEndian(rawBytes[12:14])
	ChallengeMessage.TargetNameFields.TargetNameMaxLen = decodeInt16LittleEndian(rawBytes[14:16])
	ChallengeMessage.TargetNameFields.TargetNameBufferOffset = decodeInt32LittleEndian(rawBytes[16:20])
	TargetNameFields := ChallengeMessage.TargetNameFields
	beginOffset := TargetNameFields.TargetNameBufferOffset
	endOffset := beginOffset + uint32(TargetNameFields.TargetNameLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("TargetName, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	ChallengeMessage.TargetNameFields.TargetName = rawBytes[beginOffset:endOffset]
	ChallengeMessage.NegotiateFlags = decodeInt32LittleEndian(rawBytes[20:24])
	ChallengeMessage.DecodedNegotiateFlags = DecodeNegotiateFlags(ChallengeMessage.NegotiateFlags)

	ChallengeMessage.ServerChallenge = rawBytes[24:32]
	ChallengeMessage.Reserved = rawBytes[32:40]
	ChallengeMessage.TargetInfoFields.TargetInfoLen = decodeInt16LittleEndian(rawBytes[40:42])
	ChallengeMessage.TargetInfoFields.TargetInfoMaxLen = decodeInt16LittleEndian(rawBytes[42:44])
	ChallengeMessage.TargetInfoFields.TargetInfoBufferOffset = decodeInt32LittleEndian(rawBytes[44:48])
	TargetInfoFields := ChallengeMessage.TargetInfoFields
	beginOffset = TargetInfoFields.TargetInfoBufferOffset
	endOffset = beginOffset + uint32(TargetInfoFields.TargetInfoLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("TargetInfo, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	ChallengeMessage.TargetInfoFields.TargetInfo = rawBytes[beginOffset:endOffset]
	ChallengeMessage.DecodedTargetInfo.AvPairs, err = DecodeAvPairs(ChallengeMessage.TargetInfoFields.TargetInfo)
	if err != nil {
		return nil, fmt.Errorf("TargetInfo, unable to decode TargetInfo fields, err: %v", err)
	}

	if ChallengeMessage.DecodedNegotiateFlags.NTLM_NEGOTIATE_VERSION {
		if len(rawBytes) < 54 {
			return nil, fmt.Errorf("NTLM message too short")
		}

		ChallengeMessage.Version.ProductMajorVersion = rawBytes[32]
		ChallengeMessage.Version.ProductMinorVersion = rawBytes[33]
		ChallengeMessage.Version.ProductBuild = decodeInt16LittleEndian(rawBytes[48:50])
		ChallengeMessage.Version.Reserved = rawBytes[50:53]
		ChallengeMessage.Version.NTLMRevisionCurrent = rawBytes[53]
	}

	return &ChallengeMessage, nil
}

func DecodeAuthenticateMessage(rawBytes []byte) (*AUTHENTICATE_MESSAGE, error) {
	var AuthenticateMessage AUTHENTICATE_MESSAGE
	var err error

	if len(rawBytes) < NTLM_MINIMUM_AUTHENTICATE_SIZE {
		return nil, fmt.Errorf("buffer is too short for a challenge message")
	}

	AuthenticateMessage.Signature = rawBytes[:8]
	AuthenticateMessage.MessageType = decodeInt32LittleEndian(rawBytes[8:12])
	AuthenticateMessage.LmChallengeResponseFields.LmChallengeResponseLen = decodeInt16LittleEndian(rawBytes[12:14])
	AuthenticateMessage.LmChallengeResponseFields.LmChallengeResponseMaxLen = decodeInt16LittleEndian(rawBytes[14:16])
	AuthenticateMessage.LmChallengeResponseFields.LmChallengeResponseBufferOffset = decodeInt32LittleEndian(rawBytes[16:20])
	AuthenticateMessage.NtChallengeResponseFields.NtChallengeResponseLen = decodeInt16LittleEndian(rawBytes[20:22])
	AuthenticateMessage.NtChallengeResponseFields.NtChallengeResponseMaxLen = decodeInt16LittleEndian(rawBytes[22:24])
	AuthenticateMessage.NtChallengeResponseFields.NtChallengeResponseBufferOffset = decodeInt32LittleEndian(rawBytes[24:28])
	AuthenticateMessage.DomainNameFields.DomainNameLen = decodeInt16LittleEndian(rawBytes[28:30])
	AuthenticateMessage.DomainNameFields.DomainNameMaxLen = decodeInt16LittleEndian(rawBytes[30:32])
	AuthenticateMessage.DomainNameFields.DomainNameBufferOffset = decodeInt32LittleEndian(rawBytes[32:36])
	AuthenticateMessage.UserNameFields.UserNameLen = decodeInt16LittleEndian(rawBytes[36:38])
	AuthenticateMessage.UserNameFields.UserNameMaxLen = decodeInt16LittleEndian(rawBytes[38:40])
	AuthenticateMessage.UserNameFields.UserNameBufferOffset = decodeInt32LittleEndian(rawBytes[40:44])
	AuthenticateMessage.WorkstationFields.WorkstationLen = decodeInt16LittleEndian(rawBytes[44:46])
	AuthenticateMessage.WorkstationFields.WorkstationMaxLen = decodeInt16LittleEndian(rawBytes[46:48])
	AuthenticateMessage.WorkstationFields.WorkstationBufferOffset = decodeInt32LittleEndian(rawBytes[48:52])
	AuthenticateMessage.EncryptedRandomSessionKeyFields.EncryptedRandomSessionKeyLen = decodeInt16LittleEndian(rawBytes[52:54])
	AuthenticateMessage.EncryptedRandomSessionKeyFields.EncryptedRandomSessionKeyMaxLen = decodeInt16LittleEndian(rawBytes[54:56])
	AuthenticateMessage.EncryptedRandomSessionKeyFields.EncryptedRandomSessionKeyBufferOffset = decodeInt32LittleEndian(rawBytes[56:60])
	AuthenticateMessage.NegotiateFlags = decodeInt32LittleEndian(rawBytes[60:64])
	AuthenticateMessage.DecodedNegotiateFlags = DecodeNegotiateFlags(AuthenticateMessage.NegotiateFlags)

	if AuthenticateMessage.DecodedNegotiateFlags.NTLM_NEGOTIATE_VERSION {
		if len(rawBytes) < 72 {
			return nil, fmt.Errorf("NTLM message too short")
		}

		AuthenticateMessage.Version.ProductMajorVersion = rawBytes[64]
		AuthenticateMessage.Version.ProductMinorVersion = rawBytes[65]
		AuthenticateMessage.Version.ProductBuild = decodeInt16LittleEndian(rawBytes[66:68])
		AuthenticateMessage.Version.Reserved = rawBytes[68:71]
		AuthenticateMessage.Version.NTLMRevisionCurrent = rawBytes[71]
	}

	LmChallengeResponseFields := AuthenticateMessage.LmChallengeResponseFields
	beginOffset := LmChallengeResponseFields.LmChallengeResponseBufferOffset
	endOffset := beginOffset + uint32(LmChallengeResponseFields.LmChallengeResponseMaxLen)
	AuthenticateMessage.LmChallengeResponseFields.LmChallengeResponse = rawBytes[beginOffset:endOffset]

	NtChallengeResponseFields := AuthenticateMessage.NtChallengeResponseFields
	beginOffset = NtChallengeResponseFields.NtChallengeResponseBufferOffset
	endOffset = beginOffset + uint32(NtChallengeResponseFields.NtChallengeResponseMaxLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("NtChallengeResponseFields, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	AuthenticateMessage.NtChallengeResponseFields.NtChallengeResponse = rawBytes[beginOffset:endOffset]

	DomainNameFields := AuthenticateMessage.DomainNameFields
	beginOffset = DomainNameFields.DomainNameBufferOffset
	endOffset = beginOffset + uint32(DomainNameFields.DomainNameMaxLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("DomainNameFields, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	AuthenticateMessage.DomainNameFields.DomainName = rawBytes[beginOffset:endOffset]

	UserNameFields := AuthenticateMessage.UserNameFields
	beginOffset = UserNameFields.UserNameBufferOffset
	endOffset = beginOffset + uint32(UserNameFields.UserNameMaxLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("UserNameFields, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	AuthenticateMessage.UserNameFields.UserName = rawBytes[beginOffset:endOffset]

	WorkstationFields := AuthenticateMessage.WorkstationFields
	beginOffset = WorkstationFields.WorkstationBufferOffset
	endOffset = beginOffset + uint32(WorkstationFields.WorkstationMaxLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("WorkstationFields, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	AuthenticateMessage.WorkstationFields.Workstation = rawBytes[beginOffset:endOffset]

	EncryptedRandomSessionKeyFields := AuthenticateMessage.EncryptedRandomSessionKeyFields
	beginOffset = EncryptedRandomSessionKeyFields.EncryptedRandomSessionKeyBufferOffset
	endOffset = beginOffset + uint32(EncryptedRandomSessionKeyFields.EncryptedRandomSessionKeyMaxLen)
	if endOffset > uint32(len(rawBytes)) {
		return nil, fmt.Errorf("EncryptedRandomSessionKeyFields, NTLM message too short, endOffset %d > len(rawBytes) %d", endOffset, len(rawBytes))
	}
	AuthenticateMessage.EncryptedRandomSessionKeyFields.EncryptedRandomSessionKey = rawBytes[beginOffset:endOffset]

	if len(AuthenticateMessage.NtChallengeResponseFields.NtChallengeResponse) == 24 { // NTLMv1 Detexted

	} else { // NTLMv2 Detected

		AuthenticateMessage.NtChallengeResponseFields.NTLMv2Response.Response = AuthenticateMessage.NtChallengeResponseFields.NtChallengeResponse[:16]

		ClientChallengeBytes := AuthenticateMessage.NtChallengeResponseFields.NtChallengeResponse[16:]
		AuthenticateMessage.NtChallengeResponseFields.NTLMv2Response.ClientChallenge, err = DecodeNTLMv2ClientChallenge(ClientChallengeBytes)
		if err != nil {
			return nil, fmt.Errorf("NtChallengeResponseFields, unable to decode NTLMv2 ClientChallenge: %v", err)
		}
	}

	AuthenticateMessage.MIC = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, avPair := range AuthenticateMessage.NtChallengeResponseFields.NTLMv2Response.ClientChallenge.AvPairs {
		if avPair.AvId == MsvAvFlags {
			AvFlags := decodeInt32LittleEndian(avPair.AvData[:4])
			if AvFlags&MessageIntegrityCodeIncluded == MessageIntegrityCodeIncluded {
				if len(rawBytes) < 89 {
					return nil, fmt.Errorf("NTLM message too short")
				}

				AuthenticateMessage.MIC = rawBytes[72:88]
			}
		}
	}

	return &AuthenticateMessage, nil
}

func DecodeNegotiateFlags(NegotiateFlags uint32) DECODED_NEGOTIATE_FLAGS {
	var DecodedNegotiateFlags DECODED_NEGOTIATE_FLAGS

	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE = (NegotiateFlags & (1 << 0)) != 0
	DecodedNegotiateFlags.NTLM_NEGOTIATE_OEM = (NegotiateFlags & (1 << 1)) != 0
	DecodedNegotiateFlags.NTLMSSP_REQUEST_TARGET = (NegotiateFlags & (1 << 2)) != 0
	DecodedNegotiateFlags.R10 = (NegotiateFlags & (1 << 3)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_SIGN = (NegotiateFlags & (1 << 4)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_SEAL = (NegotiateFlags & (1 << 5)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_DATAGRAM = (NegotiateFlags & (1 << 6)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY = (NegotiateFlags & (1 << 7)) != 0
	DecodedNegotiateFlags.R9 = (NegotiateFlags & (1 << 8)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_NTLM = (NegotiateFlags & (1 << 9)) != 0
	DecodedNegotiateFlags.R8 = (NegotiateFlags & (1 << 10)) != 0
	DecodedNegotiateFlags.ANONYMOUS_CONNECTION = (NegotiateFlags & (1 << 11)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED = (NegotiateFlags & (1 << 12)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = (NegotiateFlags & (1 << 13)) != 0
	DecodedNegotiateFlags.R7 = (NegotiateFlags & (1 << 14)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN = (NegotiateFlags & (1 << 15)) != 0
	DecodedNegotiateFlags.NTLMSSP_TARGET_TYPE_DOMAIN = (NegotiateFlags & (1 << 16)) != 0
	DecodedNegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER = (NegotiateFlags & (1 << 17)) != 0
	DecodedNegotiateFlags.R6 = (NegotiateFlags & (1 << 18)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = (NegotiateFlags & (1 << 19)) != 0
	DecodedNegotiateFlags.NTLMSSP_NEGOTIATE_IDENTIFY = (NegotiateFlags & (1 << 20)) != 0
	DecodedNegotiateFlags.R5 = (NegotiateFlags & (1 << 21)) != 0
	DecodedNegotiateFlags.NTLM_REQUEST_NON_NT_SESSION_KEY = (NegotiateFlags & (1 << 22)) != 0
	DecodedNegotiateFlags.NTLM_NEGOTIATE_TARGET_INFO = (NegotiateFlags & (1 << 23)) != 0
	DecodedNegotiateFlags.R4 = (NegotiateFlags & (1 << 24)) != 0
	DecodedNegotiateFlags.NTLM_NEGOTIATE_VERSION = (NegotiateFlags & (1 << 25)) != 0
	DecodedNegotiateFlags.R3 = (NegotiateFlags & (1 << 26)) != 0
	DecodedNegotiateFlags.R2 = (NegotiateFlags & (1 << 27)) != 0
	DecodedNegotiateFlags.R1 = (NegotiateFlags & (1 << 28)) != 0
	DecodedNegotiateFlags.NTLM_NEGOTIATE_128 = (NegotiateFlags & (1 << 29)) != 0
	DecodedNegotiateFlags.NTLM_NEGOTIATE_KEY_EXCH = (NegotiateFlags & (1 << 30)) != 0
	DecodedNegotiateFlags.NTLM_NEGOTIATE_56 = (NegotiateFlags & (1 << 31)) != 0

	return DecodedNegotiateFlags
}

func DecodeAvPairs(rawBytes []byte) ([]AV_PAIR, error) {
	var AvPairList []AV_PAIR

	for i := 0; i < len(rawBytes); {
		var AvPair AV_PAIR

		if len(rawBytes) < i+4 {
			return nil, fmt.Errorf("NTLM message too short")
		}
		AvPair.AvId = decodeInt16LittleEndian(rawBytes[i : i+2])
		i += 2
		AvPair.AvLen = decodeInt16LittleEndian(rawBytes[i : i+2])
		i += 2

		if len(rawBytes) < i+int(AvPair.AvLen) {
			return nil, fmt.Errorf("NTLM message too short")
		}
		AvPair.AvData = rawBytes[i : i+int(AvPair.AvLen)]
		i += int(AvPair.AvLen)

		AvPairList = append(AvPairList, AvPair)

		if AvPair.AvId == MsvAvEOL {
			return AvPairList, nil
		}
	}

	return AvPairList, fmt.Errorf("DecodeAvPairs, error list of av pairs must be terminated by MsvAvEOL")
}

func DecodeNTLMv2ClientChallenge(rawBytes []byte) (NTLMv2_CLIENT_CHALLENGE, error) {
	var NTLMv2ClientChallenge NTLMv2_CLIENT_CHALLENGE
	var err error

	NTLMv2ClientChallenge.RespType = rawBytes[0]
	NTLMv2ClientChallenge.HiRespType = rawBytes[1]
	NTLMv2ClientChallenge.Reserved1 = rawBytes[2:4]
	NTLMv2ClientChallenge.Reserved2 = rawBytes[4:8]
	NTLMv2ClientChallenge.TimeStamp = rawBytes[8:16]
	NTLMv2ClientChallenge.ChallengeFromClient = rawBytes[16:24]
	NTLMv2ClientChallenge.Reserved3 = rawBytes[24:28]

	NTLMv2ClientChallenge.AvPairs, err = DecodeAvPairs(rawBytes[28:])
	if err != nil {
		return NTLMv2ClientChallenge, err
	}

	return NTLMv2ClientChallenge, nil
}
