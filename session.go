package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/crewjam/saml"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type mattermostSessionProvider struct {
	oauthConfig *oauth2.Config
	usermap     map[string]string
}

type mattermostUser struct {
	Id string `json:"id"`
	// other fields ignored
}

func NewMattermostSessionProvider(oauthConfig *oauth2.Config, usermap map[string]string) *mattermostSessionProvider {
	return &mattermostSessionProvider{oauthConfig: oauthConfig, usermap: usermap}
}

// https://github.com/douglasmakey/oauth2-example/blob/master/handlers/oauth_google.go#L64
func generateOauthCSRFCookie(w http.ResponseWriter) string {
	var expiration = time.Now().Add(7 * 24 * time.Hour)

	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthcsrf", Value: state, Expires: expiration, Secure: true, HttpOnly: true}
	http.SetCookie(w, &cookie)

	return state
}

// SAML Request -> OAuth2 authorize
func (p *mattermostSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	// https://security.stackexchange.com/a/57886
	csrf := generateOauthCSRFCookie(w)

	state := url.Values{}
	state.Set("csrf", csrf)
	state.Set("SAMLRequest", r.URL.Query().Get("SAMLRequest"))
	state.Set("RelayState", r.URL.Query().Get("RelayState"))

	authorizeURL := p.oauthConfig.AuthCodeURL(state.Encode())
	http.Redirect(w, r, authorizeURL, http.StatusTemporaryRedirect)
	return nil
}

// OAuth2 callback -> SAML Response
func (p *mattermostSessionProvider) ServeCallback(w http.ResponseWriter, cbr *http.Request, idp *saml.IdentityProvider) {
	query, err := url.ParseQuery(cbr.URL.Query().Get("state"))
	if err != nil {
		idp.Logger.Printf("cannot parse callback state: %s", cbr.URL.Query().Get("state"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	oauthCSRF, _ := cbr.Cookie("oauthcsrf")
	if oauthCSRF == nil {
		idp.Logger.Printf("missing csrf cookie")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if query.Get("csrf") != oauthCSRF.Value {
		idp.Logger.Printf("incorrect csrf: %s", query.Get("csrf"))
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	cookie := http.Cookie{Name: "oauthcsrf", Expires: time.Unix(0, 0)}
	http.SetCookie(w, &cookie)

	// Reconstruct original SAML request
	r := &http.Request{
		Method: "GET",
		URL: &url.URL{
			RawQuery: cbr.URL.Query().Get("state"),
		},
	}

	// https://github.com/crewjam/saml/blob/v0.4.14/identity_provider.go#L225C30-L225C38
	req, err := saml.NewIdpAuthnRequest(idp, r)
	if err != nil {
		idp.Logger.Printf("failed to parse request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	if err := req.Validate(); err != nil {
		idp.Logger.Printf("failed to validate request: %s", err)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	// Finish OAuth2
	token, err := p.oauthConfig.Exchange(cbr.Context(), cbr.FormValue("code"))
	if err != nil {
		idp.Logger.Printf("code exchange wrong: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	client := p.oauthConfig.Client(cbr.Context(), token)

	// Identify user
	meResp, err := client.Get("https://test.foulab.org/api/v4/users/me")
	if err != nil {
		idp.Logger.Printf("Mattermost /api/v4/users/me error: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	defer meResp.Body.Close()
	body, err := ioutil.ReadAll(meResp.Body)
	if err != nil {
		idp.Logger.Printf("Mattermost /api/v4/users/me body error: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	idp.Logger.Printf("User: %s", body)

	var user mattermostUser
	if err := json.Unmarshal(body, &user); err != nil {
		idp.Logger.Printf("Mattermost /api/v4/users/me parse JSON error: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Username mapping
	// The only stable identifier is user.id. NOT safe to use 'username' or 'email',
	// those are controlled by the user.

	username, ok := p.usermap[user.Id]
	if !ok {
		idp.Logger.Printf("User not in usermap")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `
			<link rel="shortcut icon" href="https://foulab.org/favicon.ico" type="image/vnd.microsoft.icon" />
			<title>Foulab Authentication</title>
			<!-- match the style of Mattermost login page https://test.foulab.org/login -->
			<body style="font-family: 'Open Sans', sans-serif; font-size: 18px">
			<div style="margin: 0 auto; padding: 100px 0 50px; display: flex; max-width: 900px">
				<div style="flex: 1.3; padding-right: 80px">
					<img style="max-width: 450px" src="https://test.foulab.org/api/v4/brand/image?t=0" />
				</div>
				<div>
					<p>Sorry, your user is not yet activated for wiki access.</p>
					<p>Please post on the Mattermost <i>Tech Support</i> channel to ask to be activated.</p>
					<ul>
						<li><a href="https://test.foulab.org/foulab/channels/tech-support">Go to <i>Tech Support</i> channel now</a></li>
						<li><a href="https://laboratoires.foulab.org/w/">Go back to TikiWiki</a></li>
					</ul>
				</div>
			</div>
		`)
		return
	}

	idp.Logger.Printf("Mapped to wiki user: %s", username)

	session := &saml.Session{
		NameID:   username,
		UserName: username,
	}

	assertionMaker := idp.AssertionMaker
	if assertionMaker == nil {
		assertionMaker = saml.DefaultAssertionMaker{}
	}
	if err := assertionMaker.MakeAssertion(req, session); err != nil {
		idp.Logger.Printf("failed to make assertion: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if err := req.WriteResponse(w); err != nil {
		idp.Logger.Printf("failed to write response: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}
