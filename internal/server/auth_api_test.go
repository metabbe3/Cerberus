package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/metabbe3/cerberus/internal/audit"
	"github.com/metabbe3/cerberus/internal/auth"
)

func newTestAuthServer(t *testing.T) (*Server, *httptest.Server, *audit.Logger) {
	t.Helper()
	al, err := audit.Open(context.Background(), ":memory:", audit.Options{
		FlushEvery: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}

	authStore, err := auth.NewMemoryStore()
	if err != nil {
		t.Fatalf("auth.NewMemoryStore: %v", err)
	}

	srv := New(Deps{
		Audit:      al,
		Auth:       authStore,
		AdminToken: "test-admin-secret-token",
		Version:    "test",
	})

	ts := httptest.NewServer(srv)
	t.Cleanup(func() {
		ts.CloseClientConnections()
		ts.Close()
		_ = authStore.Close()
		_ = al.Close()
	})

	return srv, ts, al
}

func TestAuth_LoginLifecycle(t *testing.T) {
	t.Setenv("CERBERUS_ADMIN_BOOTSTRAP_PASSWORD", "AdminSecretPassword123!")
	_, ts, al := newTestAuthServer(t)

	client := ts.Client()

	// 1. Wrong password fails
	wrongBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "WrongPassword123!",
	})
	res, err := client.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(wrongBody))
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password status = %d, want 401", res.StatusCode)
	}
	_ = res.Body.Close()

	// 2. Correct password succeeds
	correctBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "AdminSecretPassword123!",
	})
	res, err = client.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(correctBody))
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login success status = %d, want 200", res.StatusCode)
	}

	var loginResp loginResponse
	if err := json.NewDecoder(res.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	_ = res.Body.Close()

	if loginResp.Token == "" || loginResp.User.Username != "admin" || loginResp.User.Role != auth.RoleAdmin {
		t.Fatalf("invalid login response: %+v", loginResp)
	}

	// 3. /v1/auth/me returns current user
	meReq, _ := http.NewRequest("GET", ts.URL+"/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	res, err = client.Do(meReq)
	if err != nil {
		t.Fatalf("me req: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("me status = %d, want 200", res.StatusCode)
	}
	var meResp struct {
		User auth.User `json:"user"`
	}
	_ = json.NewDecoder(res.Body).Decode(&meResp)
	_ = res.Body.Close()
	if meResp.User.Username != "admin" {
		t.Errorf("me username = %s, want admin", meResp.User.Username)
	}

	// 4. Logout revokes session
	logoutReq, _ := http.NewRequest("POST", ts.URL+"/v1/auth/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+loginResp.Token)
	res, err = client.Do(logoutReq)
	if err != nil {
		t.Fatalf("logout req: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("logout status = %d, want 200", res.StatusCode)
	}
	_ = res.Body.Close()

	// Old session token now rejected
	res, err = client.Do(meReq)
	if err != nil {
		t.Fatalf("me req after logout: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("status after logout = %d, want 401", res.StatusCode)
	}
	_ = res.Body.Close()

	// 5. Audit events recorded
	var evs []audit.Event
	for i := 0; i < 20; i++ {
		time.Sleep(20 * time.Millisecond)
		evs = al.Recent(50)
		if len(evs) >= 3 {
			break
		}
	}
	foundLogin := false
	foundFail := false
	foundLogout := false
	for _, ev := range evs {
		if ev.RuleID == "auth.login" {
			foundLogin = true
		}
		if ev.RuleID == "auth.login_failed" {
			foundFail = true
		}
		if ev.RuleID == "auth.logout" {
			foundLogout = true
		}
	}
	if !foundLogin || !foundFail || !foundLogout {
		t.Errorf("audit events missing: foundLogin=%v foundFail=%v foundLogout=%v, got %+v", foundLogin, foundFail, foundLogout, evs)
	}
}

func TestAuth_LockoutAfter5Fails(t *testing.T) {
	_, ts, _ := newTestAuthServer(t)
	client := ts.Client()

	wrongBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "WrongPassword123!",
	})

	for i := 1; i <= 4; i++ {
		res, err := client.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(wrongBody))
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i, res.StatusCode)
		}
		_ = res.Body.Close()
	}

	// 5th attempt locks the account
	res, err := client.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(wrongBody))
	if err != nil {
		t.Fatalf("attempt 5: %v", err)
	}
	// 5th attempt locks and returns 429
	if res.StatusCode != http.StatusTooManyRequests && res.StatusCode != http.StatusUnauthorized {
		t.Errorf("attempt 5 status = %d, want 429 or 401", res.StatusCode)
	}
	_ = res.Body.Close()

	// Subsequent attempt is blocked by lockout
	res, err = client.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(wrongBody))
	if err != nil {
		t.Fatalf("attempt 6: %v", err)
	}
	if res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("attempt 6 status = %d, want 429 (locked)", res.StatusCode)
	}
	_ = res.Body.Close()
}

func TestAuth_UserManagementAndRoleViewer(t *testing.T) {
	t.Setenv("CERBERUS_ADMIN_BOOTSTRAP_PASSWORD", "AdminSecretPassword123!")
	_, ts, al := newTestAuthServer(t)
	client := ts.Client()

	// 1. Admin logs in
	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "AdminSecretPassword123!",
	})
	res, err := client.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("admin login: %v", err)
	}
	var adminLogin loginResponse
	_ = json.NewDecoder(res.Body).Decode(&adminLogin)
	_ = res.Body.Close()

	adminToken := adminLogin.Token

	// 2. Short password validation (< 12 chars)
	shortUserBody, _ := json.Marshal(map[string]string{
		"username": "viewer1",
		"password": "short",
		"role":     "viewer",
	})
	req, _ := http.NewRequest("POST", ts.URL+"/v1/admin/users", bytes.NewReader(shortUserBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	res, err = client.Do(req)
	if err != nil {
		t.Fatalf("create user req: %v", err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("short password status = %d, want 400", res.StatusCode)
	}
	_ = res.Body.Close()

	// 3. Admin creates viewer user
	validUserBody, _ := json.Marshal(map[string]string{
		"username": "viewer1",
		"password": "ViewerPassword123!",
		"role":     "viewer",
	})
	req, _ = http.NewRequest("POST", ts.URL+"/v1/admin/users", bytes.NewReader(validUserBody))
	req.Header.Set("Authorization", "Bearer "+adminToken)
	req.Header.Set("Content-Type", "application/json")
	res, err = client.Do(req)
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create viewer status = %d, want 201", res.StatusCode)
	}
	var createdUser struct {
		User auth.User `json:"user"`
	}
	_ = json.NewDecoder(res.Body).Decode(&createdUser)
	_ = res.Body.Close()
	viewerID := createdUser.User.ID

	// 4. Viewer logs in
	vLoginBody, _ := json.Marshal(map[string]string{
		"username": "viewer1",
		"password": "ViewerPassword123!",
	})
	res, err = client.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(vLoginBody))
	if err != nil {
		t.Fatalf("viewer login: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("viewer login status = %d, want 200", res.StatusCode)
	}
	var vLogin loginResponse
	_ = json.NewDecoder(res.Body).Decode(&vLogin)
	_ = res.Body.Close()
	viewerToken := vLogin.Token

	// 5. Viewer can read (GET /v1/audit)
	getAuditReq, _ := http.NewRequest("GET", ts.URL+"/v1/audit", nil)
	getAuditReq.Header.Set("Authorization", "Bearer "+viewerToken)
	res, err = client.Do(getAuditReq)
	if err != nil {
		t.Fatalf("viewer audit: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("viewer get audit status = %d, want 200", res.StatusCode)
	}
	_ = res.Body.Close()

	// 6. Viewer is FORBIDDEN on mutating endpoints (403)
	// (a) PUT /v1/admin/data
	putReq, _ := http.NewRequest("PUT", ts.URL+"/v1/admin/data", bytes.NewReader([]byte("{}")))
	putReq.Header.Set("Authorization", "Bearer "+viewerToken)
	putReq.Header.Set("Content-Type", "application/json")
	res, err = client.Do(putReq)
	if err != nil {
		t.Fatalf("viewer put: %v", err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer put data status = %d, want 403 Forbidden", res.StatusCode)
	}
	_ = res.Body.Close()

	// (b) POST /v1/admin/reload
	reloadReq, _ := http.NewRequest("POST", ts.URL+"/v1/admin/reload", nil)
	reloadReq.Header.Set("Authorization", "Bearer "+viewerToken)
	res, err = client.Do(reloadReq)
	if err != nil {
		t.Fatalf("viewer reload: %v", err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer reload status = %d, want 403 Forbidden", res.StatusCode)
	}
	_ = res.Body.Close()

	// (c) GET /v1/admin/users (viewer cannot manage users)
	usersReq, _ := http.NewRequest("GET", ts.URL+"/v1/admin/users", nil)
	usersReq.Header.Set("Authorization", "Bearer "+viewerToken)
	res, err = client.Do(usersReq)
	if err != nil {
		t.Fatalf("viewer list users: %v", err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer list users status = %d, want 403 Forbidden", res.StatusCode)
	}
	_ = res.Body.Close()

	// 7. Admin disables viewer
	disableBody, _ := json.Marshal(map[string]bool{"disabled": true})
	disReq, _ := http.NewRequest("POST", ts.URL+"/v1/admin/users/"+time.Duration(viewerID).String(), bytes.NewReader(disableBody))
	disReq, _ = http.NewRequest("POST", ts.URL+fmt.Sprintf("/v1/admin/users/%d/disable", viewerID), bytes.NewReader(disableBody))
	disReq.Header.Set("Authorization", "Bearer "+adminToken)
	disReq.Header.Set("Content-Type", "application/json")
	res, err = client.Do(disReq)
	if err != nil {
		t.Fatalf("admin disable viewer: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("disable viewer status = %d, want 200", res.StatusCode)
	}
	_ = res.Body.Close()

	// Disabled viewer session is now rejected
	res, err = client.Do(getAuditReq)
	if err != nil {
		t.Fatalf("disabled viewer audit req: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Errorf("disabled viewer status = %d, want 401", res.StatusCode)
	}
	_ = res.Body.Close()

	// 8. Admin resets password and re-enables
	enableBody, _ := json.Marshal(map[string]bool{"disabled": false})
	enReq, _ := http.NewRequest("POST", ts.URL+fmt.Sprintf("/v1/admin/users/%d/disable", viewerID), bytes.NewReader(enableBody))
	enReq.Header.Set("Authorization", "Bearer "+adminToken)
	enReq.Header.Set("Content-Type", "application/json")
	res, err = client.Do(enReq)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("re-enable failed: %v", err)
	}
	_ = res.Body.Close()

	resetBody, _ := json.Marshal(map[string]string{"password": "BrandNewPassword123!"})
	resetReq, _ := http.NewRequest("POST", ts.URL+fmt.Sprintf("/v1/admin/users/%d/reset-password", viewerID), bytes.NewReader(resetBody))
	resetReq.Header.Set("Authorization", "Bearer "+adminToken)
	resetReq.Header.Set("Content-Type", "application/json")
	res, err = client.Do(resetReq)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("reset password failed: %v", err)
	}
	_ = res.Body.Close()

	// Viewer logs in with new password
	newLoginBody, _ := json.Marshal(map[string]string{
		"username": "viewer1",
		"password": "BrandNewPassword123!",
	})
	res, err = client.Post(ts.URL+"/v1/auth/login", "application/json", bytes.NewReader(newLoginBody))
	if err != nil {
		t.Fatalf("viewer login new pass: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Errorf("viewer login new pass status = %d, want 200", res.StatusCode)
	}
	_ = res.Body.Close()

	// 9. Check audit events
	var evs []audit.Event
	for i := 0; i < 20; i++ {
		time.Sleep(20 * time.Millisecond)
		evs = al.Recent(50)
		if len(evs) >= 4 {
			break
		}
	}
	ruleMap := make(map[string]bool)
	for _, ev := range evs {
		ruleMap[ev.RuleID] = true
	}
	if !ruleMap["auth.user_created"] {
		t.Errorf("missing auth.user_created audit event, got %+v", evs)
	}
	if !ruleMap["auth.user_disabled"] {
		t.Errorf("missing auth.user_disabled audit event, got %+v", evs)
	}
	if !ruleMap["auth.password_reset"] {
		t.Errorf("missing auth.password_reset audit event, got %+v", evs)
	}
}
