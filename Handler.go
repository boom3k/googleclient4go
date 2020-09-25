package googleclient4go

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/boom3k/utils4go"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
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

//ServiceAccount------------------------------------------------------------------------------------------------------_/

func InitJWTConfig(serviceAccountEmail, privateKey, privateKeyID string, scopes []string) *jwt.Config {
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

func InitJWTConfigUsingFile(serviceAccountKeyPath string, scopes []string) *jwt.Config {
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

func GetServiceAccountClient(jwt *jwt.Config, subjectEmail string) *http.Client {
	jwt.Subject = subjectEmail
	return jwt.Client(context.Background())
}

/*Deprecated Start*/
/*func GetJWT(userEmail, serviceAccountKeyPath string) *jwt.Config {
	file, err := ioutil.ReadFile(serviceAccountKeyPath)
	utils4go.CatchException(err)
	jwtConfig, err := google.JWTConfigFromJSON(file)
	utils4go.CatchException(err)
	jwtConfig.Subject = userEmail
	return jwtConfig
}
func GetServiceAccountClientUsingFile(userEmail, serviceAccountKeyPath string, userScopes []string) *http.Client {
	jwtConfig := GetJWT(userEmail, serviceAccountKeyPath)
	if userScopes == nil {
		userScopes = defaultServiceAccountScopes
	}
	jwtConfig.Scopes = userScopes
	return jwtConfig.Client(context.Background())
}*/
/*Deprecated End*/

//OAuth2---------------------------------------------------------------------------------------------------------------/
func InitOAuth2Config(clientID, clientSecret string) *oauth2.Config {
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

func InitOAuth2ConfigUsingFile(filepath string) *oauth2.Config {
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

func GetOAuth2Client(clientId, clientSecret, accessToken, refreshToken, expiry string) *http.Client {
	config := InitOAuth2Config(clientId, clientSecret)
	time, err := time.Parse(timeFormat, expiry)
	if err != nil {
		panic(err)
	}
	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		Expiry:       time}
	return config.Client(context.Background(), token)

}

func GetOAuth2ClientFromClientSecretTokensFile(filepath string) *http.Client {
	fileAsJSON := utils4go.ParseJSONFileToMap(filepath)
	clientId := utils4go.GetJsonValue(fileAsJSON["installed"], "client_id").(string)
	clientSecret := utils4go.GetJsonValue(fileAsJSON["installed"], "client_secret").(string)
	accesstoken := utils4go.GetJsonValue(fileAsJSON["oauth2"], "access_token").(string)
	refreshToken := utils4go.GetJsonValue(fileAsJSON["oauth2"], "refresh_token").(string)
	expiry := utils4go.GetJsonValue(fileAsJSON["oauth2"], "expiry").(string)
	return GetOAuth2Client(clientId, clientSecret, accesstoken, refreshToken, expiry)
}

func WriteClientSecretTokensFile(adminEmail string, scopes []string, oauth2 *oauth2.Config, tokens *oauth2.Token) {
	FILEDATA := make(map[string]interface{})
	FILEDATA["installed"] = oauth2
	FILEDATA["oauth2_tokens"] = tokens
	FILEDATA["scopes"] = scopes
	adminInfo := make(map[string]interface{})
	adminInfo["adminEmail"] = adminEmail
	adminInfo["domain"] = strings.Split(adminEmail, "@")[1]
	oauth2Client := GetOAuth2Client(
		oauth2.ClientID,
		oauth2.ClientSecret,
		tokens.AccessToken,
		tokens.RefreshToken,
		tokens.Expiry.String())
	directoryService, err := admin.NewService(context.Background(), option.WithHTTPClient(oauth2Client))
	if err != nil {
		panic(err)
		log.Fatal(err)
	}
	user, err := directoryService.Users.Get(adminEmail).Do()
	if err != nil {
		panic(err)
		log.Fatal(err)
	}
	adminInfo["customer_id"] = user.CustomerId
	FILEDATA["authenticated_user"] = adminInfo
	projectId := utils4go.GetJsonValue(FILEDATA["installed"], "project_id").(string)
	userName := strings.Split(adminEmail, "@")[0]
	file, err := os.OpenFile(userName+"_"+projectId+".json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
		log.Fatal(err)
	}
	defer file.Close()
	json.NewEncoder(file).Encode(FILEDATA)
}

/*Deprecated Start*/
/*func GetOAuth2ClientUsingFile(clientSecretTokensFilePath string) *http.Client {
	fileAsJSON := utils4go.ParseJSONFileToMap(clientSecretTokensFilePath)
	clientId := utils4go.GetJsonValue(fileAsJSON["installed"], "client_id").(string)
	clientSecret := utils4go.GetJsonValue(fileAsJSON["installed"], "client_secret").(string)
	accesstoken := utils4go.GetJsonValue(fileAsJSON["oauth2"], "access_token").(string)
	refreshToken := utils4go.GetJsonValue(fileAsJSON["oauth2"], "refresh_token").(string)
	expiry := utils4go.GetJsonValue(fileAsJSON["oauth2"], "expiry").(string)
	return GetOAuth2Client(clientId, clientSecret, accesstoken, refreshToken, expiry)
}

func SimpleOAuth2TokenGenerator(clientSecretsFilePath string, scopes []string) {
	bytes, err := ioutil.ReadFile(clientSecretsFilePath)
	utils4go.CatchException(err)
	oauth2Config, err := google.ConfigFromJSON(bytes)
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
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	utils4go.CatchException(err)
	tokenResponse, err := config.Exchange(context.TODO(), input)
	utils4go.CatchException(err)
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
	configFile, err := ioutil.ReadFile(clientSecretFilePath)
	utils4go.CatchException(err)
	oauth2Config, err := google.ConfigFromJSON(configFile)
	utils4go.CatchException(err)
	oauth2Client := GetOAuth2Client(
		oauth2Config.ClientID,
		oauth2Config.ClientSecret,
		tokens.AccessToken,
		tokens.RefreshToken,
		tokens.Expiry.String())
	directoryService, err := admin.NewService(context.Background(), option.WithHTTPClient(oauth2Client))
	utils4go.CatchException(err)
	user, err := directoryService.Users.Get(adminEmail).Do()
	utils4go.CatchException(err)
	adminInfo["customer_id"] = user.CustomerId
	FILEDATA["authenticated_user"] = adminInfo
	projectId := utils4go.GetJsonValue(FILEDATA["installed"], "project_id").(string)
	file, err := os.OpenFile(projectId+"_token.json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	utils4go.CatchException(err)
	defer file.Close()
	json.NewEncoder(file).Encode(FILEDATA)
}*/
/*Deprecated End*/
