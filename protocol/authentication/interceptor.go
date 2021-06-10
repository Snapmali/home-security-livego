package authentication

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gwuhaolin/livego/configure"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

const (
	Success          = 0
	InvalidToken     = 301
	LoginAgainNeeded = 302
	InternalError    = 500
	DatabaseFailure  = 501

	ContentTypeJson = "application/json"
)

type BaseResponse struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type Response struct {
	w      http.ResponseWriter
	Status int          `json:"status"`
	Data   BaseResponse `json:"data"`
}

func (r *Response) SendJson(status int, code int, message string) (int, error) {
	r.Status = status
	r.Data.Code = code
	r.Data.Message = message
	resp, _ := json.Marshal(r.Data)
	r.w.Header().Set("Content-Type", ContentTypeJson)
	r.w.WriteHeader(r.Status)
	return r.w.Write(resp)
}

type Claims struct {
	jwt.StandardClaims
	UserId uint64 `json:"user_id"`
}

func HttpInterceptor(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		res := Response{
			w:      w,
			Status: http.StatusOK,
			Data:   BaseResponse{},
		}
		tokenString, authErr := GetTokenString(r)
		if authErr != nil {
			log.Info("Failed to get the token")
			res.SendJson(http.StatusUnauthorized, InvalidToken, authErr.Error())
			return
		}
		body := map[string]interface{}{
			"id":     0,
			"jwt":    tokenString,
			"verify": true,
		}
		jsonStr, _ := json.Marshal(body)
		authResp, authErr := http.Post(
			configure.Config.GetString("auth_server_url")+"/auth/auth_jwt",
			ContentTypeJson,
			bytes.NewBuffer(jsonStr))
		var respData BaseResponse
		if authResp == nil {
			log.Info("Failed to auth: ", authErr)
			res.SendJson(http.StatusInternalServerError, InternalError, authErr.Error())
			return
		}
		jsonErr := json.NewDecoder(authResp.Body).Decode(&respData)
		if jsonErr != nil {
			if authErr == nil {
				log.Info("Failed to decode the response: ", jsonErr)
				res.SendJson(http.StatusInternalServerError, InternalError, jsonErr.Error())
				return
			}
			log.Info("Failed to auth: ", authErr)
			res.SendJson(http.StatusInternalServerError, InternalError, authErr.Error())
			return
		}
		if respData.Code != Success {
			log.Info("Invalid token: ", respData.Message)
			res.SendJson(authResp.StatusCode, respData.Code, respData.Message)
			return
		}
		h(w, r)
	}
}

// GetTokenString gets token string from HTTP Authorization request header
func GetTokenString(r *http.Request) (string, error) {
	data, ok := r.Header["Authorization"]
	if !ok {
		return "", errors.New("no auth method found")
	}
	tokenString := data[0]
	if tokenString == "" {
		return "", errors.New("token not found")
	}
	if !strings.HasPrefix(tokenString, "Bearer ") {
		return "", errors.New("token format error")
	}
	tokenString = tokenString[7:]
	if tokenString == "" {
		return "", errors.New("token not found")
	}
	return tokenString, nil
}
