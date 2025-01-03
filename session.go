package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"github.com/crewjam/saml"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type mattermostSessionProvider struct {
	oauthConfig *oauth2.Config
	usermap     *sql.DB
}

type mattermostUser struct {
	Id       string `json:"id"`
	Username string `json:"username"`
	// other fields ignored
}

func NewMattermostSessionProvider(oauthConfig *oauth2.Config, usermap *sql.DB) *mattermostSessionProvider {
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

	// By default, clear CSRF cookie as soon as the flow is complete. Note some
	// code paths ('Continue' interstitial) override this before returning.
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
		idp.Logger.Printf("OAuth code exchange error: %s", err.Error())
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

	if user.Username == "admin" {
		idp.Logger.Printf("Mattermost Username 'admin' not allowed")
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// Username mapping
	// The only stable identifier is user.id. Fields like 'username' or 'email'
	// are controlled by the user and can be changed at will.

	var username string
	row := p.usermap.QueryRow(`SELECT tikiwiki_username FROM usermap WHERE mattermost_id = ?`, user.Id)
	err = row.Scan(&username)
	if err == sql.ErrNoRows { // No user for this Mattermost ID
		idp.Logger.Printf("User not in usermap")

		// Check if there is already a wiki account with this username.
		//
		// This is RACY, because someone can create an account between this SELECT
		// and the INSERT which creates the account.
		//
		// The INSERT below (and the UNIQUE INDEX) is the mechanism which
		// atomically enforces uniqueness.
		var dummy int
		row = p.usermap.QueryRow(`SELECT 1 FROM usermap WHERE tikiwiki_username = ?`, user.Username)
		err = row.Scan(&dummy)
		if err == sql.ErrNoRows { // No user for this Mattermost Username
			if cbr.FormValue("continue") == "" {
				// Keep the CSRF cookie until the flow is complete.
				w.Header().Del("Set-Cookie")

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
							<h2>You are creating a wiki account with your Mattermost username <i>%s</i>.</h2>
							<p><b>All your wiki edits, chat messages, forum posts, etc, will be permanently
							linked to this username.</b></p>
							<p>The username cannot be changed once the account is created.</p>
							<p>If you want to change this username, go back and
							<a href="https://docs.mattermost.com/preferences/manage-your-profile.html" target="_blank">
							modify your Mattermost profile</a>, then try to access the wiki again.</p>
							<p>If you have any questions, feel free to post on Mattermost
							<a href="https://test.foulab.org/foulab/channels/tech-support" target="_blank">Tech Support</a> channel.</p>
							<form action="%s" method="post">
								<input type="submit" name="continue" value="Continue with this username ›" style="font-size: 100%%" />
							</form>
						</div>
					</div>
				`, html.EscapeString(user.Username), html.EscapeString(cbr.URL.RequestURI()))

				// TODO: This does not actually work, 'Continue' can't exchange the
				// OAuth2 code a second time:
				/*
				2025/01/03 17:03:53 70.80.21.217 POST /matterid/callback?code=<redacted>&state=<redacted>
				2025/01/03 17:03:53 code exchange wrong: oauth2: cannot fetch token: 400 Bad Request
				Response: {"id":"api.oauth.get_access_token.expired_code.app_error","message":"invalid_grant: Invalid or expired authorization code.","detailed_error":"","request_id":"5fszmwz1w38uubpo6mx9rydo5a","status_code":400}
				*/

				return
			} else {
				// Very Important: ensures uniqueness of ID <-> Username mapping.
				_, err = p.usermap.Exec(
					`INSERT INTO usermap (mattermost_id, tikiwiki_username, created_at) VALUES (?, ?, ?)`,
					user.Id, user.Username, time.Now())
				if err != nil {
					idp.Logger.Printf("usermap insert error: %s", err.Error())
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			}
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
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
						<h2>Sorry, there is already a wiki account with the Mattermost username <i>%s</i>.</h2>
						<p>The same username cannot be used to create a new account.</p>
						<p>If you want to try with a different username, go back and
						<a href="https://docs.mattermost.com/preferences/manage-your-profile.html" target="_blank">
						modify your Mattermost profile</a>, then try to access the wiki again.</p>
						<p>If you have any questions, feel free to post on Mattermost
						<a href="https://test.foulab.org/foulab/channels/tech-support" target="_blank">Tech Support</a> channel.</p>
					</div>
				</div>
			`, html.EscapeString(user.Username))
			return
		}
	} else if err != nil {
		idp.Logger.Printf("Usermap query error: %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else {
		// User found, fall through
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
