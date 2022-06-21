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

const (

	// NTLM message size minimum sizes
	NTLM_MINIMUM_HEADER_SIZE       = 12
	NTLM_MINIMUM_NEGOTIATE_SIZE    = 32
	NTLM_MINIMUM_CHALLENGE_SIZE    = 48
	NTLM_MINIMUM_AUTHENTICATE_SIZE = 64

	// NTLM Message Types
	MESSAGE_TYPE_NEGOTIATE    = 0x1
	MESSAGE_TYPE_CHALLENGE    = 0x2
	MESSAGE_TYPE_AUTHENTICATE = 0x3

	// NTLM Valid AvId Values
	MsvAvEOL             = 0x0000
	MsvAvNbComputerName  = 0x0001
	MsvAvNbDomainName    = 0x0002
	MsvAvDnsComputerName = 0x0003
	MsvAvDnsDomainName   = 0x0004
	MsvAvDnsTreeName     = 0x0005
	MsvAvFlags           = 0x0006
	MsvAvTimestamp       = 0x0007
	MsvAvSingleHost      = 0x0008
	MsvAvTargetName      = 0x0009
	MsvChannelBindings   = 0x000A

	// MsvAvFlags Values
	AccountAuthenticationConstrained = 0x00000001
	MessageIntegrityCodeIncluded     = 0x00000002
	ServicePrincipalNameIncluded     = 0x00000004
)

var (
	NTLM_SIGNATURE = [8]byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00}
)

type NEGOTIATE_MESSAGE struct {
	Signature             []byte
	MessageType           uint32
	NegotiateFlags        uint32
	DecodedNegotiateFlags DECODED_NEGOTIATE_FLAGS
	DomainNameFields      struct {
		DomainNameLen          uint16
		DomainNameMaxLen       uint16
		DomainNameBufferOffset uint32
		DomainName             []byte
	}
	WorkstationFields struct {
		WorkstationLen          uint16
		WorkstationMaxLen       uint16
		WorkstationBufferOffset uint32
		WorkstationName         []byte
	}
	Version NTLM_VERSION_INFO_DEBUG
}

type CHALLENGE_MESSAGE struct {
	Signature        []byte
	MessageType      uint32
	TargetNameFields struct {
		TargetNameLen          uint16
		TargetNameMaxLen       uint16
		TargetNameBufferOffset uint32
		TargetName             []byte
	}
	NegotiateFlags        uint32
	DecodedNegotiateFlags DECODED_NEGOTIATE_FLAGS
	ServerChallenge       []byte
	Reserved              []byte
	TargetInfoFields      struct {
		TargetInfoLen          uint16
		TargetInfoMaxLen       uint16
		TargetInfoBufferOffset uint32
		TargetInfo             []byte
	}
	DecodedTargetInfo DECODED_TARGET_INFO
	Version           NTLM_VERSION_INFO_DEBUG
}

type AUTHENTICATE_MESSAGE struct {
	Signature                 []byte
	MessageType               uint32
	LmChallengeResponseFields struct {
		LmChallengeResponseLen          uint16
		LmChallengeResponseMaxLen       uint16
		LmChallengeResponseBufferOffset uint32
		LmChallengeResponse             []byte
	}
	NtChallengeResponseFields struct {
		NtChallengeResponseLen          uint16
		NtChallengeResponseMaxLen       uint16
		NtChallengeResponseBufferOffset uint32
		NtChallengeResponse             []byte
		NTLMv2Response                  NTLMv2_RESPONSE
	}
	DomainNameFields struct {
		DomainNameLen          uint16
		DomainNameMaxLen       uint16
		DomainNameBufferOffset uint32
		DomainName             []byte
	}
	UserNameFields struct {
		UserNameLen          uint16
		UserNameMaxLen       uint16
		UserNameBufferOffset uint32
		UserName             []byte
	}
	WorkstationFields struct {
		WorkstationLen          uint16
		WorkstationMaxLen       uint16
		WorkstationBufferOffset uint32
		Workstation             []byte
	}
	EncryptedRandomSessionKeyFields struct {
		EncryptedRandomSessionKeyLen          uint16
		EncryptedRandomSessionKeyMaxLen       uint16
		EncryptedRandomSessionKeyBufferOffset uint32
		EncryptedRandomSessionKey             []byte
	}
	NegotiateFlags        uint32
	DecodedNegotiateFlags DECODED_NEGOTIATE_FLAGS
	Version               NTLM_VERSION_INFO_DEBUG
	MIC                   []byte
}

type NTLM_VERSION_INFO_DEBUG struct {
	ProductMajorVersion uint8
	ProductMinorVersion uint8
	ProductBuild        uint16
	Reserved            []byte
	NTLMRevisionCurrent byte
}

type DECODED_NEGOTIATE_FLAGS struct {
	NTLM_NEGOTIATE_56                          bool
	NTLM_NEGOTIATE_KEY_EXCH                    bool
	NTLM_NEGOTIATE_128                         bool
	R1                                         bool
	R2                                         bool
	R3                                         bool
	NTLM_NEGOTIATE_VERSION                     bool
	R4                                         bool
	NTLM_NEGOTIATE_TARGET_INFO                 bool
	NTLM_REQUEST_NON_NT_SESSION_KEY            bool
	R5                                         bool
	NTLMSSP_NEGOTIATE_IDENTIFY                 bool
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY bool
	R6                                         bool
	NTLMSSP_TARGET_TYPE_SERVER                 bool
	NTLMSSP_TARGET_TYPE_DOMAIN                 bool
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN              bool
	R7                                         bool
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED bool
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      bool
	ANONYMOUS_CONNECTION                       bool
	R8                                         bool
	NTLMSSP_NEGOTIATE_NTLM                     bool
	R9                                         bool
	NTLMSSP_NEGOTIATE_LM_KEY                   bool
	NTLMSSP_NEGOTIATE_DATAGRAM                 bool
	NTLMSSP_NEGOTIATE_SEAL                     bool
	NTLMSSP_NEGOTIATE_SIGN                     bool
	R10                                        bool
	NTLMSSP_REQUEST_TARGET                     bool
	NTLM_NEGOTIATE_OEM                         bool
	NTLMSSP_NEGOTIATE_UNICODE                  bool
}

type DECODED_TARGET_INFO struct {
	AvPairs []AV_PAIR
}

type AV_PAIR struct {
	AvId   uint16
	AvLen  uint16
	AvData []byte
}

type NTLMv2_RESPONSE struct {
	Response        []byte
	ClientChallenge NTLMv2_CLIENT_CHALLENGE
}

type NTLMv2_CLIENT_CHALLENGE struct {
	RespType            byte
	HiRespType          byte
	Reserved1           []byte
	Reserved2           []byte
	TimeStamp           []byte
	ChallengeFromClient []byte
	Reserved3           []byte
	AvPairs             []AV_PAIR
}
