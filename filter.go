package captcha

import (
	"github.com/bytepowered/flux"
	"github.com/bytepowered/flux/common"
	"github.com/dchest/captcha"
)

var _ flux.Filter = new(CaptchaFilter)

const (
	FilterIdCaptcha = "captcha_filter"
)

type CaptchaConfig struct {
	LookupScope string
	IdKey       string
	ValueKey    string
}

type CaptchaFilter struct {
	config CaptchaConfig
}

func NewCaptchaFilterWith(c CaptchaConfig) *CaptchaFilter {
	return &CaptchaFilter{
		config: c,
	}
}

func NewCaptchaFilter() *CaptchaFilter {
	return NewCaptchaFilterWith(CaptchaConfig{
		LookupScope: flux.ScopeForm,
		IdKey:       "captchaId",
		ValueKey:    "captchaValue",
	})
}

func (c *CaptchaFilter) FilterId() string {
	return FilterIdCaptcha
}

func (c *CaptchaFilter) DoFilter(next flux.FilterInvoker) flux.FilterInvoker {
	return func(ctx *flux.Context) *flux.ServeError {
		id, value := common.LookupWebValue(ctx, c.config.LookupScope, c.config.IdKey),
			common.LookupWebValue(ctx, c.config.LookupScope, c.config.ValueKey)
		if id == "" || "" == value {
			return &flux.ServeError{
				StatusCode: flux.StatusBadRequest,
				ErrorCode:  "SERVER:CAPTCHA:VERIFY/args",
				Message:    "SERVER:CAPTCHA/id,value:notfound",
			}
		}
		if captcha.VerifyString(id, value) {
			return next(ctx)
		}
		return &flux.ServeError{
			StatusCode: flux.StatusBadRequest,
			ErrorCode:  "SERVER:CAPTCHA:VERIFY/error",
			Message:    "SERVER:CAPTCHA/not-match",
		}
	}
}
