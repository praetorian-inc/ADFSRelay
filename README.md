# Overview 

This repository includes two utilities NTLMParse and ADFSRelay. NTLMParse is a utility for decoding base64-encoded NTLM messages and printing information about the underlying properties and fields within the message. Examining these NTLM messages is helpful when researching the behavior of a particular NTLM implementation. ADFSRelay is a proof of concept utility developed while researching the feasibility of NTLM relaying attacks targeting the ADFS service. This utility can be leveraged to perform NTLM relaying attacks targeting ADFS.

TODO: Reference and link to the published blog post

# NTLMParse Usage

To use the NTLMParse utility you simply need to pass a Base64 encoded message to the application and it will decode the relevant fields and structures within the message. The snippet given below shows the expected output of NTLMParse when it is invoked:

```
➜  ~ pbpaste | NTLMParse
(ntlm.AUTHENTICATE_MESSAGE) {
 Signature: ([]uint8) (len=8 cap=585) {
  00000000  4e 54 4c 4d 53 53 50 00                           |NTLMSSP.|
 },
 MessageType: (uint32) 3,
 LmChallengeResponseFields: (struct { LmChallengeResponseLen uint16; LmChallengeResponseMaxLen uint16; LmChallengeResponseBufferOffset uint32; LmChallengeResponse []uint8 }) {
  LmChallengeResponseLen: (uint16) 24,
  LmChallengeResponseMaxLen: (uint16) 24,
  LmChallengeResponseBufferOffset: (uint32) 160,
  LmChallengeResponse: ([]uint8) (len=24 cap=425) {
   00000000  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
   00000010  00 00 00 00 00 00 00 00                           |........|
  }
 },
 NtChallengeResponseFields: (struct { NtChallengeResponseLen uint16; NtChallengeResponseMaxLen uint16; NtChallengeResponseBufferOffset uint32; NtChallengeResponse []uint8; NTLMv2Response ntlm.NTLMv2_RESPONSE }) {
  NtChallengeResponseLen: (uint16) 384,
  NtChallengeResponseMaxLen: (uint16) 384,
  NtChallengeResponseBufferOffset: (uint32) 184,
  NtChallengeResponse: ([]uint8) (len=384 cap=401) {
   00000000  30 eb 30 1f ab 4f 37 4d  79 59 28 73 38 51 19 3b  |0.0..O7MyY(s8Q.;|
   00000010  01 01 00 00 00 00 00 00  89 5f 6d 5c c8 72 d8 01  |........._m\.r..|
   00000020  c9 74 65 45 b9 dd f7 35  00 00 00 00 02 00 0e 00  |.teE...5........|
   00000030  43 00 4f 00 4e 00 54 00  4f 00 53 00 4f 00 01 00  |C.O.N.T.O.S.O...|
   00000040  1e 00 57 00 49 00 4e 00  2d 00 46 00 43 00 47 00  |..W.I.N.-.F.C.G.|
```

# ADFSRelay Usage

ADFSRelay has a single required argument, the URL of the ADFS server to target for an NTLM relaying attack. In addition to this, there are three optional arguments -debug to enable debugging mode, -port to define the port the service should listen on, and -help to display the help menu. An example help menu is given below:

```
➜  ~ ADFSRelay -h
Usage of ADFSRelay:
  -debug
    	Enables debug output
  -help
    	Show the help menu
  -port int
    	The port the HTTP listener should listen on (default 8080)
  -targetSite string
    	The ADFS site to target for the relaying attack (e.g. https://sts.contoso.com)
➜  ~
```

# References
[1] TODO: LINK TO BLOG POST
