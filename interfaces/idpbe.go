package interfaces

type AuthenticateRequest struct {
  Id              string            `json:"id"`
  Password        string            `json:"password"`
  Challenge       string            `json:"challenge" binding:"required"`
}

type AuthenticateResponse struct {
  Id              string            `json:"id"`
  Authenticated   bool              `json:"authenticated"`
  RedirectTo      string            `json:"redirect_to,omitempty"`
}

type LogoutRequest struct {
  Challenge       string            `json:"challenge" binding:"required"`
}

type LogoutResponse struct {
  RedirectTo      string            `json:"redirect_to" binding:"required"`
}
