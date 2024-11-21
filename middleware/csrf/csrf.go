package csrf

import (
	"net/http"

	"github.com/danecwalker/gosec/helpers/crypto"
)

type CSRFConfig struct {
	TokenHeaderName string
	TokenCookieName string
	ErrorHandler    http.Handler
	GenerateToken   func() string // optional
}

var defaultConfig = CSRFConfig{
	TokenHeaderName: "X-CSRF-Token",
	TokenCookieName: "csrf_token",
	ErrorHandler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "CSRF token mismatch", http.StatusForbidden)
	}),
	GenerateToken: func() string {
		return crypto.RandomString(32)
	},
}

func Middleware(config *CSRFConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = &defaultConfig
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			token := r.FormValue(config.TokenCookieName)
			if token == "" {
				token = r.Header.Get(config.TokenHeaderName)
			}

			cookie, err := r.Cookie(config.TokenCookieName)
			// fmt.Println(cookie.Value, token)
			if err != nil || cookie.Value != token {
				config.ErrorHandler.ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func RequestSetter(config *CSRFConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = &defaultConfig
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(config.TokenCookieName)
			if err != nil || cookie.Value == "" {
				token := config.GenerateToken()
				cookie = &http.Cookie{
					Name:  config.TokenCookieName,
					Value: token,
					Path:  "/",
				}
				http.SetCookie(w, cookie)
			}

			next.ServeHTTP(w, r)
		})
	}
}

type TemplateSetterMapJoiner func(map[string]any) map[string]any

func TemplateSetter(config *CSRFConfig) func(w http.ResponseWriter) TemplateSetterMapJoiner {
	if config == nil {
		config = &defaultConfig
	}

	return func(w http.ResponseWriter) TemplateSetterMapJoiner {
		token := config.GenerateToken()
		cookie := &http.Cookie{
			Name:  config.TokenCookieName,
			Value: token,
			Path:  "/",
		}
		http.SetCookie(w, cookie)

		return func(m map[string]any) map[string]any {
			m["csrfToken"] = token
			m["csrfTokenName"] = config.TokenCookieName
			m["csrfFormSnippet"] = `<input type="hidden" name="` + config.TokenCookieName + `" value="` + token + `">`
			return m
		}
	}
}
