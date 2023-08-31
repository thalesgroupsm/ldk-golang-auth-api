package auth_client

type AuthToken struct {
	AccessToken      string  `json:"access_token"`
	ExpiresIn        float64 `json:"expires_in"`
	TokenType        string  `json:"token_type"`
	IdToken          string  `json:"id_token"`
	RefreshExpiresIn float64 `json:"refresh_expires_in"`
	RefreshToken     string  `json:"refresh_token"`
	NotBeforePolicy  float64 `json:"not-before-policy"`
	SessionState     string  `json:"session_state"`
	Scope            string  `json:"scope"`
}
