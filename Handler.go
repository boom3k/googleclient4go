package googleclient4go

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/boom3k/utils4go"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

func main() {
}

var timeFormat = "2006-01-02T15:04:05Z07:00"
var defaultOAuth2Scopes = []string{"https://www.googleapis.com/auth/admin.reports.audit.readonly",
	"https://www.googleapis.com/auth/admin.reports.usage.readonly",
	"https://www.googleapis.com/auth/admin.directory.user",
	"https://www.googleapis.com/auth/admin.directory.group.member",
	"https://www.googleapis.com/auth/admin.directory.group",
	"https://www.googleapis.com/auth/admin.directory.customer",
	"https://www.googleapis.com/auth/admin.directory.resource.calendar",
	"https://www.googleapis.com/auth/admin.directory.domain",
	"https://www.googleapis.com/auth/apps.groups.settings",
	"https://www.googleapis.com/auth/androidmanagement",
	"https://www.googleapis.com/auth/apps.groups.migration",
	"https://www.googleapis.com/auth/apps.groups.settings",
	"https://www.googleapis.com/auth/admin.datatransfer",
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/cloud_search",
	"https://www.googleapis.com/auth/apps.licensing",
	"https://www.googleapis.com/auth/admin.directory.device.mobile"}
var defaultServiceAccountScopes = []string{"https://www.googleapis.com/auth/drive",
	"https://mail.google.com/",
	"https://sites.google.com/feeds",
	"https://www.google.com/m8/feeds",
	"https://www.googleapis.com/auth/activity",
	"https://www.googleapis.com/auth/calendar",
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/contacts",
	"https://www.googleapis.com/auth/gmail.settings.basic",
	"https://www.googleapis.com/auth/gmail.settings.sharing",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile"}

//ServiceAccount-------------------------------------------------------------------------------------------------------/
func SetJWTConfig(serviceAccountEmail, privateKey, privateKeyID string, scopes []string) *jwt.Config {
	return &jwt.Config{Email: serviceAccountEmail,
		PrivateKey:    []uint8(privateKey)[:],
		PrivateKeyID:  privateKeyID,
		Scopes:        scopes,
		TokenURL:      "https://oauth2.googleapis.com/token",
		Expires:       time.Duration(0),
		Audience:      "",
		PrivateClaims: nil,
		UseIDToken:    false}
}

func SetJWTConfigUsingFile(serviceAccountKeyPath string, scopes []string) *jwt.Config {
	file, err := ioutil.ReadFile(serviceAccountKeyPath)
	if err != nil {
		panic(err)
	}
	jwtConfig, err := google.JWTConfigFromJSON(file)
	if err != nil {
		panic(err)
	}
	jwtConfig.Scopes = scopes
	return jwtConfig
}

func GetServiceAccountHttpClient(jwt *jwt.Config, subjectEmail string) *http.Client {
	jwt.Subject = subjectEmail
	return jwt.Client(context.Background())
}

//OAuth2---------------------------------------------------------------------------------------------------------------/
func SetOAuth2Config(clientID, clientSecret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  "https://oauth2.googleapis.com/token",
			AuthStyle: oauth2.AuthStyleAutoDetect},
	}
}

func SetOAuth2ConfigUsingFile(filepath string) *oauth2.Config {
	fileData, err := ioutil.ReadFile(filepath)
	if err != nil {
		panic(err)
	}
	config, _ := google.ConfigFromJSON(fileData)
	if err != nil {
		panic(err)
	}
	return config
}

func GetOAuth2TokensFromWeb(oauth2Config *oauth2.Config, scopes []string) *oauth2.Token {
	oauth2Config.Scopes = scopes
	authenticationURL := oauth2Config.AuthCodeURL("state-oauth2Token", oauth2.AccessTypeOffline)
	fmt.Println("Go to the following link in your browser then type the authorization code:", authenticationURL)
	fmt.Println("Enter the code:")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}
	cliResponse, err := oauth2Config.Exchange(context.TODO(), input)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return cliResponse
}

func GetOauth2HttpClient(clientId, clientSecret, accessToken, refreshToken string, expiry time.Time) *http.Client {
	config := SetOAuth2Config(clientId, clientSecret)
	/*time, err := time.Parse(timeFormat, expiry)
	if err != nil {
		panic(err)
	}*/
	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		Expiry:       expiry}
	return config.Client(context.Background(), token)

}

func GetHttpClientFromCustomToken(filepath string) *http.Client {
	fileAsJSON := utils4go.ParseJSONFileToMap(filepath)
	clientId := utils4go.GetJsonValue(fileAsJSON["installed"], "client_id").(string)
	clientSecret := utils4go.GetJsonValue(fileAsJSON["installed"], "client_secret").(string)
	accesstoken := utils4go.GetJsonValue(fileAsJSON["oauth2"], "access_token").(string)
	refreshToken := utils4go.GetJsonValue(fileAsJSON["oauth2"], "refresh_token").(string)
	expiry := utils4go.GetJsonValue(fileAsJSON["oauth2"], "expiry").(time.Time)
	return GetOauth2HttpClient(clientId, clientSecret, accesstoken, refreshToken, expiry)
}

//Tokens File----------------------------------------------------------------------------------------------------------/
func WriteClientSecretTokensFile(adminEmail string, scopes []string, oauth2 *oauth2.Config, tokens *oauth2.Token) {
	FILEDATA := make(map[string]interface{})
	FILEDATA["installed"] = oauth2
	FILEDATA["oauth2_tokens"] = tokens
	adminInfo := make(map[string]interface{})
	adminInfo["adminEmail"] = adminEmail
	domain := strings.Split(adminEmail, "@")[1]
	adminInfo["domain"] = domain
	FILEDATA["authenticated_user"] = adminInfo
	userName := strings.Split(adminEmail, "@")[0]
	file, err := os.OpenFile(userName+"_"+strings.ReplaceAll(domain, ".", "_")+".json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		panic(err)
		log.Fatal(err)
	}
	defer file.Close()
	json.NewEncoder(file).Encode(FILEDATA)
}
