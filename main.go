package googleclient4go

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/boom3k/utils4go"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var timeFormat = "2006-01-02T15:04:05Z07:00"
var AdminScopes = []string{
	"https://www.googleapis.com/auth/admin.reports.audit.readonly",
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
	"https://www.googleapis.com/auth/cloudplatformprojects",
	"https://www.googleapis.com/auth/cloud_search",
	"https://www.googleapis.com/auth/apps.licensing",
	"https://www.googleapis.com/auth/admin.directory.device.mobile"}
var GenericServiceAccountScopes = []string{
	"https://mail.google.com/",
	"https://sites.google.com/feeds",
	"https://www.google.com/m8/feeds",
	"https://www.googleapis.com/auth/drive",
	"https://www.googleapis.com/auth/activity",
	"https://www.googleapis.com/auth/calendar",
	"https://www.googleapis.com/auth/contacts",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
	"https://www.googleapis.com/auth/gmail.settings.basic",
	"https://www.googleapis.com/auth/gmail.settings.sharing",
}

func main() {
}

//ServiceAccount-------------------------------------------------------------------------------------------------------/
/* Returns a type jwt.Config from content that would be found in a Google Cloud Service Account's key file*/
func GetJWTConfigManually(serviceAccountEmail, privateKey, privateKeyID string, scopes []string) *jwt.Config {
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

/* Returns a type jwt.Config from content from a type Google ServiceAccounts key file*/
func GetJWTConfigUsingKeyfile(serviceAccountKeyPath string, scopes []string) (*jwt.Config, error) {
	file, err := ioutil.ReadFile(serviceAccountKeyPath)
	if err != nil {
		return nil, err
	}
	jwtConfig, err := google.JWTConfigFromJSON(file)
	if err != nil {
		return nil, err
	}
	jwtConfig.Scopes = scopes
	return jwtConfig, nil
}

/* Returns a type Service Account http.Client from an jwt.Config*/
func GetServiceAccountHttpClientUsingJWT(jwt *jwt.Config, subjectEmail string) *http.Client {
	jwt.Subject = subjectEmail
	log.Println("ServiceAccount [" + jwt.Email + "] is acting as --> [" + subjectEmail + "]")
	return jwt.Client(context.Background())
}

/* Returns a type Service Account http.Client from content that would be found in a Google Cloud Service Account's key file*/
func GetServiceAccountHttpClient(subjectEmail, serviceAccountEmail, privateKey, privateKeyID string, scopes []string) *http.Client {
	jwt := GetJWTConfigManually(serviceAccountEmail, privateKey, privateKeyID, scopes)
	return GetServiceAccountHttpClientUsingJWT(jwt, subjectEmail)
}

//OAuth2---------------------------------------------------------------------------------------------------------------/
/* Returns a type oauth2.Config from a client id and secret*/
func GetOAuth2Config(clientID, clientSecret string) *oauth2.Config {
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

/* Returns a type oauth2.Config from a given clientSecrets filepath*/
func GetOAuth2ConfigFromFile(clientSecretsFilePath string) (*oauth2.Config, error) {
	fileData, err := ioutil.ReadFile(clientSecretsFilePath)
	if err != nil {
		return nil, err
	}
	return GetOauth2ConfigFromBytes(fileData)
}

func GetOauth2ConfigFromBytes(data []byte) (*oauth2.Config, error) {
	config, err := google.ConfigFromJSON(data)
	if err != nil {
		return nil, err
	}
	return config, nil
}

/* Returns a type oauth2.token from a given type oauth2.Config*/
func GetOAuth2TokensFromBrowser(oauth2Config *oauth2.Config, scopes []string) *oauth2.Token {
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

/* Returns a type http.Client from content found in a typical clientSecrets file*/
func GetOAuth2HttpClient(clientId, clientSecret, accessToken, refreshToken string, expiry time.Time) *http.Client {
	config := GetOAuth2Config(clientId, clientSecret)
	token := &oauth2.Token{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		Expiry:       expiry}
	return config.Client(context.Background(), token)
}

func GetOAuth2HttpClientFromEncryptedFile(filepath, sixteenCharKey string) *http.Client {
	tokenFileData, _ := utils4go.DecryptFile(filepath, sixteenCharKey)
	config, _ := google.ConfigFromJSON(tokenFileData)
	tokenDataMap := utils4go.ParseJsonFileBytesToMap(tokenFileData)
	oauth2Tokens := tokenDataMap["oauth2_tokens"].(map[string]interface{})
	expiry, err := time.Parse(timeFormat, oauth2Tokens["expiry"].(string))
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	return GetOAuth2HttpClient(config.ClientID, config.ClientSecret, oauth2Tokens["access_token"].(string), oauth2Tokens["refresh_token"].(string), expiry)
}

/* Returns a type http.Client from content found in a typical clientSecrets file*/
func GetOAuth2ConfigFromClientSecretsFile(oAuth2FilePath string) (*oauth2.Config, error) {
	oauthConfig, err := GetOAuth2ConfigFromFile(oAuth2FilePath)
	return oauthConfig, err
}

/* Returns a type http.Client from a give clientSecrets filepath*/
func GetOauth2HttpClientFromAuthenticatedToken(filepath string) (*http.Client, error) {
	fileAsJSON, err := utils4go.ParseJSONFileToMap(filepath)
	if err != nil {
		return nil, err
	}
	clientId := utils4go.GetJsonValue(fileAsJSON["installed"], "client_id").(string)
	clientSecret := utils4go.GetJsonValue(fileAsJSON["installed"], "client_secret").(string)
	accessToken := utils4go.GetJsonValue(fileAsJSON["oauth2_tokens"], "access_token").(string)
	refreshToken := utils4go.GetJsonValue(fileAsJSON["oauth2_tokens"], "refresh_token").(string)
	expiry, err := time.Parse(timeFormat, utils4go.GetJsonValue(fileAsJSON["oauth2_tokens"], "expiry").(string))
	if err != nil {
		panic(err)
	}
	return GetOAuth2HttpClient(clientId, clientSecret, accessToken, refreshToken, expiry), nil
}

//Setup Stuff----------------------------------------------------------------------------------------------------------/
func GenerateCustomOAuth2Token(clientID, clientSecret, tokenFileName string, oauth2Scopes []string, addServiceAccountScopes bool) (*os.File, error) {
	userName := utils4go.Readline("Enter your userEmail: ")
	/*Set oauth2Config using ClientID and ClientSecret*/
	oauth2Config := GetOAuth2Config(clientID, clientSecret)
	/*Get tokens from web using OAuth2*/
	tokens := GetOAuth2TokensFromBrowser(oauth2Config, oauth2Scopes)
	/*Write token file*/
	return CreateCustomClientSecretsFile(userName, tokenFileName, addServiceAccountScopes, oauth2Config, tokens)
}
func GenerateEncryptedCustomOAuth2TokenFile(clientSecretFileData []byte, tokenName string, scopes []string, addServiceAccountScopes, overwriteExistingFile bool) (string, error) {
	config, err := GetOauth2ConfigFromBytes(clientSecretFileData)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	tokenFile, err := GenerateCustomOAuth2Token(config.ClientID, config.ClientSecret, tokenName, scopes, addServiceAccountScopes)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	return utils4go.EncryptFile(tokenFile.Name(), utils4go.Readline("Enter a password for the tokenFile: (Mininum: 16 characters)"), overwriteExistingFile)
}
func GenerateCustomOauth2TokenUsingFile(Oauth2FilePath, newTokenFileName string, oauth2Scopes []string, addServiceAccountScopes bool) (*os.File, error) {
	userName := utils4go.Readline("Enter your userEmail: ")
	/*Set oauth2Config using ClientID and ClientSecret*/
	oauth2Config, err := GetOAuth2ConfigFromFile(Oauth2FilePath)
	if err != nil {
		log.Println(err.Error())
		panic(err)
	}
	/*Get tokens from web using OAuth2*/
	tokens := GetOAuth2TokensFromBrowser(oauth2Config, oauth2Scopes)
	/*Write token file*/
	return CreateCustomClientSecretsFile(userName, newTokenFileName, addServiceAccountScopes, oauth2Config, tokens)
}

//Tokens File----------------------------------------------------------------------------------------------------------/
func CreateCustomClientSecretsFile(userEmail, fileName string, addServiceAccountScopes bool, oauth2 *oauth2.Config, tokens *oauth2.Token) (*os.File, error) {
	FILEDATA := make(map[string]interface{})
	var installed = make(map[string]interface{})
	installed["client_id"] = oauth2.ClientID
	installed["auth_uri"] = oauth2.Endpoint.AuthURL
	installed["token_uri"] = oauth2.Endpoint.TokenURL
	installed["client_secret"] = oauth2.ClientSecret
	redirectUris := []string{oauth2.RedirectURL, "http://localhost"}
	installed["redirect_uris"] = redirectUris
	FILEDATA["installed"] = installed
	//FILEDATA["installed"] = oauth2
	FILEDATA["oauth2_tokens"] = tokens
	if addServiceAccountScopes == true {
		FILEDATA["serviceaccountscopes"] = GenericServiceAccountScopes
	}
	adminInfo := make(map[string]interface{})
	adminInfo["userEmail"] = userEmail
	domain := strings.Split(userEmail, "@")[1]
	adminInfo["domain"] = domain
	FILEDATA["authenticated_user"] = adminInfo
	file, err := os.OpenFile(fileName+".json", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return file, err
	}
	defer file.Close()
	json.NewEncoder(file).Encode(FILEDATA)
	return file, err
}
func TokenToMap(token *oauth2.Token) map[string]interface{} {
	tokenMap := make(map[string]interface{})
	tokenMap["token_type"] = token.TokenType
	tokenMap["access_token"] = token.AccessToken
	tokenMap["refresh_token"] = token.RefreshToken
	tokenMap["expiry"] = token.Expiry
	return tokenMap
}
