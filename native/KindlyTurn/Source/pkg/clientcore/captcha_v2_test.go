package clientcore

import (
	"context"
	"io"
	"net/url"
	"strings"
	"testing"

	fhttp "github.com/bogdanfinn/fhttp"
	tlsclient "github.com/bogdanfinn/tls-client"
)

// New VK BFF pages load initSession at runtime, rather than embedding window.init.
const bffCaptchaFixture = `<script>window.isBFF = true; window.vk = {brlefapmjnpg: "test-release-id"};</script>
<script src="https://st.vk.ru/vkid/vkid-bff/dist/projects/notRobotCaptcha-web/entrypoints/entry.test.js" async></script>
<script>(function(a,b,c,d){ window['captchaPowResult']='v2.'; }('test-pow-input',2,'pow_timeout',[]));</script>`

func TestParseCaptchaV2BothPageGenerations(t *testing.T) {
	t.Parallel()
	old := `<script>window.init = {"data":{"show_captcha_type":"checkbox","captcha_settings":[]}};
 const powInput = "old-input"; const difficulty = 2;</script>
 <script src="https://st.vk.ru/vkid/1.1.1324/not_robot_captcha.js"></script>`
	for _, tc := range []struct {
		name, html, pow string
		bff             bool
	}{
		{"legacy", old, "old-input", false}, {"BFF", bffCaptchaFixture, "test-pow-input", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := parseCaptchaV2Page(tc.html)
			if err != nil {
				t.Fatal(err)
			}
			if page.BFF != tc.bff || page.PowInput != tc.pow || page.PowDifficulty != 2 {
				t.Fatalf("unexpected page: %#v", page)
			}
			if tc.bff && page.DebugInfo != "test-release-id" {
				t.Fatal("BFF release id missing")
			}
		})
	}
}

func TestCaptchaRejectsIncompleteOrUnboundedPage(t *testing.T) {
	t.Parallel()
	for _, html := range []string{"<html>Service unavailable</html>", strings.Replace(bffCaptchaFixture, ",2,", ",9999,", 1), strings.Replace(bffCaptchaFixture, "brlefapmjnpg:", "unknown:", 1)} {
		if _, err := parseCaptchaV2Page(html); err == nil {
			t.Fatal("expected unsupported page error")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if solveCaptchaPoWV2(ctx, "input", 2) != "" {
		t.Fatal("cancelled verification continued")
	}
	if solveCaptchaPoWV2(context.Background(), "input", 1000) != "" {
		t.Fatal("unbounded difficulty accepted")
	}
}

type captchaTestClient struct {
	tlsclient.HttpClient
	do func(*fhttp.Request) (*fhttp.Response, error)
}

func (c *captchaTestClient) Do(r *fhttp.Request) (*fhttp.Response, error) { return c.do(r) }

func TestBFFCaptchaCompletesNativelyWithoutBrowser(t *testing.T) {
	t.Parallel()
	var calls []string
	client := &captchaTestClient{do: func(r *fhttp.Request) (*fhttp.Response, error) {
		method := r.URL.Path
		calls = append(calls, method)
		body := `{"response":{}}`
		switch method {
		case "/challenge":
			body = bffCaptchaFixture
		case "/method/captchaNotRobot.initSession":
			body = `{"response":{"show_captcha_type":"checkbox","content_settings":[{"type":"slider","settings_key":"slider-key"}]}}`
		case "/method/captchaNotRobot.check":
			raw, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(raw))
			if form.Get("debug_info") != "test-release-id" || !strings.HasPrefix(form.Get("hash"), "00") {
				t.Fatal("new page proof/release id not sent")
			}
			body = `{"response":{"status":"OK","success_token":"test-success"}}`
		}
		return &fhttp.Response{StatusCode: 200, Header: make(fhttp.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	}}
	session := &captchaV2Session{ctx: context.Background(), client: client}
	token, err := session.solveOnce(&VkCaptchaError{RedirectURI: "https://id.vk.ru/challenge", SessionToken: "test-session"})
	if err != nil || token != "test-success" {
		t.Fatalf("verification: token=%q error=%v", token, err)
	}
	expected := "/challenge,/method/captchaNotRobot.initSession,/method/captchaNotRobot.settings,/method/captchaNotRobot.componentDone,/method/captchaNotRobot.check,/method/captchaNotRobot.endSession"
	if strings.Join(calls, ",") != expected {
		t.Fatalf("unexpected calls: %v", calls)
	}
}
