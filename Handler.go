package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/boom3k/utils4go"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

func main() {
	SimpleOAuth2TokenGenerator(utils4go.Readline("ClientSecretFilePath: "), nil)
	/*fmt.Println("Build: Reduce")
	SimpleOAuth2TokenGenerator("client_secrets.json", nil)
	defer os.Exit(0)*/
}

var timeFormat = "2006-01-02T15:04:05Z07:00"

//Add new Oauth2 Scopes Here
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

/*ServiceAccount------------------------------------------------------------------------------------------------------*/
func GetJWT(userEmail, serviceAccountKeyPath string) *jwt.Config {
	file, _ := ioutil.ReadFile(serviceAccountKeyPath)
	jwtConfig, _ := google.JWTConfigFromJSON(file)
	jwtConfig.Subject = userEmail
	return jwtConfig
}

func GetServiceAccountClient(userEmail, serviceAccountKeyPath string, userScopes []string) *http.Client {
	jwtConfig := GetJWT(userEmail, serviceAccountKeyPath)
	if userScopes == nil {
		userScopes = defaultServiceAccountScopes
	}
	jwtConfig.Scopes = userScopes
	return jwtConfig.Client(context.Background())
}

/*OAuth2--------------------------------------------------------------------------------------------------------------*/
func GetOAuth2Client(clientId, clientSecret, accessToken, refreshToken, expiry string) *http.Client {
	config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  "https://oauth2.googleapis.com/token",
			AuthStyle: oauth2.AuthStyleAutoDetect},
	}
	time, _ := time.Parse(timeFormat, expiry)
	oAuth2Tokens := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		Expiry:       time}
	oAuth2Tokens.AccessToken = accessToken
	oAuth2Tokens.RefreshToken = refreshToken
	return config.Client(context.Background(), oAuth2Tokens)
}

func GetOAuth2ClientUsingFile(clientSecretTokensFilePath string) *http.Client {
	fileAsJSON := utils4go.ParseJSONFileToMap(clientSecretTokensFilePath)
	clientId := utils4go.GetJsonValue(fileAsJSON["installed"], "client_id").(string)
	clientSecret := utils4go.GetJsonValue(fileAsJSON["installed"], "client_secret").(string)
	accesstoken := utils4go.GetJsonValue(fileAsJSON["oauth2_tokens"], "access_token").(string)
	refreshToken := utils4go.GetJsonValue(fileAsJSON["oauth2_tokens"], "refresh_token").(string)
	expiry := utils4go.GetJsonValue(fileAsJSON["oauth2_tokens"], "expiry").(string)
	return GetOAuth2Client(clientId, clientSecret, accesstoken, refreshToken, expiry)
}

func SimpleOAuth2TokenGenerator(clientSecretsFilePath string, scopes []string) {
	bytes, _ := ioutil.ReadFile(clientSecretsFilePath)
	oauth2Config, _ := google.ConfigFromJSON(bytes)
	if scopes == nil {
		scopes = defaultOAuth2Scopes
		for i := range defaultServiceAccountScopes {
			scopes = append(scopes, defaultServiceAccountScopes[i])
		}
	}
	oauth2Config.Scopes = scopes
	adminEmail := utils4go.Readline("Enter your admin email address: ")
	tokens := GetTokensFromOAuth2Flow(oauth2Config.ClientID, oauth2Config.ClientSecret, oauth2Config.Scopes)
	WriteTokens(adminEmail, clientSecretsFilePath, *tokens, defaultServiceAccountScopes)
}

func GetTokensFromOAuth2Flow(clientId, clientSecret string, scopes []string) *oauth2.Token {
	config := &oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Scopes:       scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  "https://oauth2.googleapis.com/token",
			AuthStyle: oauth2.AuthStyleAutoDetect},
	}
	authenticationURL := config.AuthCodeURL("state-oauth2Token", oauth2.AccessTypeOffline)
	fmt.Println("Go to the following link in your browser then type the authorization code:", authenticationURL)
	fmt.Println("Enter the code:")
	input, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	tokenResponse, _ := config.Exchange(context.TODO(), input)
	return tokenResponse
}

func WriteTokens(adminEmail, clientSecretFilePath string, tokens oauth2.Token, scopes []string) {
	FILEDATA := make(map[string]interface{})
	clientSecretFileJSON := utils4go.ParseJSONFileToMap(clientSecretFilePath)
	FILEDATA["installed"] = utils4go.GetJsonValue(clientSecretFileJSON, "installed")
	FILEDATA["oauth2"] = tokens
	FILEDATA["scopes"] = scopes
	adminInfo := make(map[string]interface{})
	adminInfo["adminEmail"] = adminEmail
	adminInfo["domain"] = strings.Split(adminEmail, "@")[1]
	configFile, _ := ioutil.ReadFile(clientSecretFilePath)
	oauth2Config, _ := google.ConfigFromJSON(configFile)
	oauth2Client := GetOAuth2Client(
		oauth2Config.ClientID,
		oauth2Config.ClientSecret,
		tokens.AccessToken,
		tokens.RefreshToken,
		tokens.Expiry.String())
	directoryService, _ := admin.NewService(context.Background(), option.WithHTTPClient(oauth2Client))
	user, err := directoryService.Users.Get(adminEmail).Do()
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
		os.Exit(0)
	}
	adminInfo["customer_id"] = user.CustomerId
	FILEDATA["authenticated_user"] = adminInfo
	projectId := utils4go.GetJsonValue(FILEDATA["installed"], "project_id").(string)
	file, _ := os.OpenFile(projectId+"_token.json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer file.Close()
	json.NewEncoder(file).Encode(FILEDATA)
}
