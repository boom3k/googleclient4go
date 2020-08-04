package main
import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"os"
	"time"

	"github.com/boom3k/utils4go"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

func main() {
}

var timeFormat = "2006-01-02T15:04:05Z07:00"
var adminScopes = []string{"https://www.googleapis.com/auth/admin.reports.audit.readonly",
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
	"https://www.googleapis.com/auth/admin.directory.device.mobile",
}
var userScopes = []string{"https://www.googleapis.com/auth/drive",
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

// GetJWTFromFile rfgs
func GetJWTFromFile(serviceAccountKeyData []byte) *jwt.Config {
	jwtConfig := utils4go.GetObj(google.JWTConfigFromJSON(serviceAccountKeyData)).(*jwt.Config)
	return jwtConfig
}

// GetUserJWT feaf
func GetUserJWT(subject string) *jwt.Config {
	jwtConfig := GetJWTFromFile(utils4go.ReadFile("sakey.json"))
	jwtConfig.Subject = subject
	return jwtConfig
}

// GetServiceAccountClient returns the http.Client using a serviceaccount credential jwt.Config type
func GetServiceAccountClient(serviceAccountCredential jwt.Config) *http.Client {
	serviceAccountCredential.Scopes = userScopes
	client := serviceAccountCredential.Client(context.Background())
	return client
}

// GetOauth2ClientFromFilepath Retrieves http.Client using the clientSecrets file via the given filepath
func GetOauth2ClientFromFilepath(clientSecretsFilePath string) *http.Client {
	config := &oauth2.Config{}
	config = utils4go.GetObj(google.ConfigFromJSON(utils4go.ReadFile(clientSecretsFilePath))).(*oauth2.Config)
	token := &oauth2.Token{}
	tokenJson := utils4go.ReadJsonFile(clientSecretsFilePath)["tokens"]
	token.AccessToken = utils4go.GetJsonKey(tokenJson, "access_token").(string)
	token.RefreshToken = utils4go.GetJsonKey(tokenJson, "refresh_token").(string)
	token.TokenType = utils4go.GetJsonKey(tokenJson, "token_type").(string)
	expiry := utils4go.GetJsonKey(tokenJson, "expiry").(string)
	token.Expiry = utils4go.GetObj(time.Parse(timeFormat, expiry)).(time.Time)
	return config.Client(context.Background(), token)
}

// Generates the token
func GenerateTokens(clientSecretsFilePath string) {
	//Extract jsonData from the JsonFile
	jsonData := utils4go.ReadFile(clientSecretsFilePath)
	clientSecretJson := make(map[string]interface{})
	clientSecretJson["installed"] = utils4go.ReadJsonFile(clientSecretsFilePath)["installed"]
	oauth2Config := utils4go.GetObj(google.ConfigFromJSON(jsonData)).(*oauth2.Config)
	oauth2Config.Scopes = adminScopes
	for i := range userScopes {
		oauth2Config.Scopes = append(oauth2Config.Scopes, userScopes[i])
	}

	tokenMap := make(map[string]interface{})
	tokenMap["created"] = time.Now().Format("Monday, 2006-January-02, 15:04:05PM ")
	tokenMap["oauth2_scopes"] = adminScopes
	tokenMap["service_account_scopes"] = userScopes
	userEmail := utils4go.ReadLine("Enter your admin email: ")
	tokenMap["authorized_user"] = userEmail
	tokens := beginOauth2Flow(oauth2Config)
	tokenMap["access_token"] = tokens.AccessToken
	tokenMap["refresh_token"] = tokens.RefreshToken
	tokenMap["token_type"] = tokens.TokenType
	tokenMap["expiry"] = tokens.Expiry
	clientSecretJson["tokens"] = tokenMap
	newClientSecretsFilePath := "cstokens.json"
	fmt.Println("Saving tokens to:", newClientSecretsFilePath)
	file := utils4go.GetObj(os.OpenFile(newClientSecretsFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)).(*os.File)
	defer file.Close()
	json.NewEncoder(file).Encode(clientSecretJson)
}

//
func beginOauth2Flow(oauth2Config *oauth2.Config) *oauth2.Token {
	//Via Web, generate the authentication URL from the oauth2Config file
	authenticationURL := oauth2Config.AuthCodeURL("state-oauth2Token", oauth2.AccessTypeOffline)
	fmt.Println("Go to the following link in your browser then type the authorization code:", authenticationURL)
	tokens := utils4go.GetObj(oauth2Config.Exchange(context.TODO(), utils4go.ReadLine("Enter the code:"))).(*oauth2.Token)
	return tokens
}