package main

/*
OAuth2 -> SAML federation proxy, with custom Mattermost user mapping.

Mattermost OAuth2 support: https://developers.mattermost.com/integrate/apps/authentication/oauth2/
TikiWiki SAML support: https://doc.tiki.org/SAML
Architecture: https://docs.google.com/drawings/d/1-6bG3IhrlQCuBbebG-6gK_R6q9T9Eyuw_OX5DGoC0iU/edit

Custom user mapping: Mattermost username and e-mail can be changed by the user,
so they are *not* reliable stable user identifiers. The stable user ID is the
internal user ID (eg. "j5rxg5sp538puyifp7dbhiotwo"). TikiWiki uses usernames as
stable user identifier. So, we need an explicit mapping from Mattermost user ID
to TikiWiki username.

Related work:
	https://github.com/chaosloth/saml-oauth-bridge
	https://github.com/IdentityPython/SATOSA
	https://stackoverflow.com/questions/53227919/proxy-on-top-of-oidc-idp-provider-to-accept-saml-requests-from-service-provider
	https://www.keycloak.org/docs/latest/server_admin/index.html#_identity_broker_oidc
	https://wiki.geant.org/display/GSPP/Technical+Information
	https://lemonldap-ng.org/documentation/2.0/federationproxy.html
*/

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// https://workos.com/docs/sso/signing-certificates/saml-response-signing-certificate
// openssl req -x509 -newkey rsa:2048 -keyout matterid.key -out matterid.crt -days 3650 -nodes -subj "/CN=auth.foulab.org"
var crtFile = flag.String("crt", "matterid.crt", "IdP certificate")
var keyFile = flag.String("key", "matterid.key", "IdP private key")

var baseURL = flag.String("baseURL", "https://auth.foulab.org/matterid", "IdP base URL (excluding /metadata)")

var serviceProvidersGlob = flag.String("serviceProvidersGlob", "tikiwiki.xml", "Glob for service provider metadata XML. IdP will only accept requests from these SPs.")

// Note: MUST run behind a reverse proxy that adds TLS
var port = flag.Int("port", 8007, "Port for HTTP server")

func openUsermap() *sql.DB {
	db, err := sql.Open("sqlite3", "usermap.sqlite3")
	if err != nil {
		log.Fatalf("Usermap open error: %s\n", err)
	}

	// PRIMARY KEY / UNIQUE are very important, they enforce that one user cannot
	// impersonate another.
	const create = `
		CREATE TABLE IF NOT EXISTS usermap (
			mattermost_id TEXT NOT NULL PRIMARY KEY,
			tikiwiki_username TEXT NOT NULL,
			created_at DATETIME
		);
		CREATE UNIQUE INDEX IF NOT EXISTS usermap_tikiwiki_username ON usermap (
			tikiwiki_username
		);
	`
	if _, err := db.Exec(create); err != nil {
		log.Fatalf("Usermap create table error: %s\n", err)
	}

	var count int
	row := db.QueryRow(`SELECT COUNT(*) FROM usermap`)
	if err = row.Scan(&count); err != nil {
		log.Fatalf("Usermap query count error: %s\n", err)
	}
	log.Printf("usermap: %d entries", count)

	return db
}

func readOAuthClientSecret() string {
	b, err := os.ReadFile("oauth-client-secret")
	if err != nil {
		panic(err)
	}

	return strings.TrimRight(string(b), "\n")
}

// https://blog.kowalczyk.info/article/e00e89c3841e4f8c8c769a78b8a90b47/logging-http-requests-in-go.html

// Request.RemoteAddress contains port, which we want to remove i.e.:
// "[::1]:58292" => "[::1]"
func ipAddrFromRemoteAddr(s string) string {
	idx := strings.LastIndex(s, ":")
	if idx == -1 {
		return s
	}
	return s[:idx]
}

// requestGetRemoteAddress returns ip address of the client making the request,
// taking into account http proxies
func requestGetRemoteAddress(r *http.Request) string {
	hdr := r.Header
	hdrRealIP := hdr.Get("X-Real-Ip")
	hdrForwardedFor := hdr.Get("X-Forwarded-For")
	if hdrRealIP == "" && hdrForwardedFor == "" {
		return ipAddrFromRemoteAddr(r.RemoteAddr)
	}
	if hdrForwardedFor != "" {
		// X-Forwarded-For is potentially a list of addresses separated with ","
		parts := strings.Split(hdrForwardedFor, ",")
		for i, p := range parts {
			parts[i] = strings.TrimSpace(p)
		}
		// TODO: should return first non-local address
		return parts[0]
	}
	return hdrRealIP
}

func main() {
	logr := logger.DefaultLogger
	flag.Parse()

	// OAuth2 client
	// https://github.com/douglasmakey/oauth2-example
	mattermostOauthConfig := &oauth2.Config{
		RedirectURL:  *baseURL + "/callback",
		ClientID:     "8ts1zi7j8jyiffr8bgzbgysc4w",
		ClientSecret: readOAuthClientSecret(),
		// https://github.com/mattermost/mattermost/blob/773ab352e845e1313c4b6a273ad1aae19e31f58c/app/oauth.go#L176
		Scopes: []string{"user"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://test.foulab.org/oauth/authorize",
			TokenURL:  "https://test.foulab.org/oauth/access_token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	usermap := openUsermap()
	defer usermap.Close()

	sessionProvider := NewMattermostSessionProvider(mattermostOauthConfig, usermap)

	// SAML IdP
	baseURL, err := url.Parse(*baseURL)
	if err != nil {
		logr.Fatalf("cannot parse base URL: %v", err)
	}

	keyPair, err := tls.LoadX509KeyPair(*crtFile, *keyFile)
	if err != nil {
		logr.Fatalf("cannot load key pair: %v", err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		logr.Fatalf("cannot parse certificate: %v", err)
	}

	metadataURL := *baseURL
	metadataURL.Path += "/metadata"
	ssoURL := *baseURL
	ssoURL.Path += "/sso"

	idp := &saml.IdentityProvider{
		Key:                     keyPair.PrivateKey,
		Logger:                  logr,
		Certificate:             keyPair.Leaf,
		MetadataURL:             metadataURL,
		SSOURL:                  ssoURL,
		ServiceProviderProvider: NewFileServiceProvider(*serviceProvidersGlob),
		SessionProvider:         sessionProvider,
	}
	http.HandleFunc(idp.MetadataURL.Path, idp.ServeMetadata)
	http.HandleFunc(idp.SSOURL.Path, idp.ServeSSO)

	// OAuth2 callback
	http.HandleFunc(baseURL.Path+"/callback", func(w http.ResponseWriter, cbr *http.Request) {
		sessionProvider.ServeCallback(w, cbr, idp)
	})

	// Ensure requests are from localhost (from a reverse proxy that hopefully
	// adds TLS) -- SAML assertions are bearer tokens and must be protected.
	ensureLocalClient := func(w http.ResponseWriter, r *http.Request) {
		// Redact query parameter values (eg. OAuth authorization codes)
		urlRedacted := regexp.MustCompile(`=[^&]+(&|$)`).ReplaceAllString(r.URL.String(), "=<redacted>$1")
		logr.Printf("%s %s %s\n", requestGetRemoteAddress(r), r.Method, urlRedacted)
		w.Header().Set("Server", "matterid/0.1")

		var a *net.TCPAddr
		if a, err = net.ResolveTCPAddr("tcp", r.RemoteAddr); err != nil {
			logr.Printf("cannot parse RemoteAddr: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if !a.IP.IsLoopback() {
			logr.Printf("RemoteAddr is not loopback: %v", a.IP)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		http.DefaultServeMux.ServeHTTP(w, r)
	}

	err = http.ListenAndServe("127.0.0.1:"+strconv.Itoa(*port), http.HandlerFunc(ensureLocalClient))
	if err != nil {
		logr.Panicf("listen: %v", err)
		return
	}
}
