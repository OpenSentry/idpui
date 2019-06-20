package interfaces

type AuthenticateRequest struct {
  Id              string            `json:"id" binding:"required"`
  Password        string            `json:"password" binding:"required"`
  Challenge       string            `json:"challenge" binding:"required"`
}

type AuthenticateResponse struct {
  Id              string            `json:"id"`
  Authenticated   bool              `json:"authenticated"`
  RedirectTo      string            `json:"redirect_to,omitempty"`
}
