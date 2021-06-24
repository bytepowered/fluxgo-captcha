package captcha

import (
	"strings"
)

import (
	"github.com/dchest/captcha"
)

import (
	"github.com/bytepowered/fluxgo/pkg/common"
	"github.com/bytepowered/fluxgo/pkg/flux"
	"github.com/bytepowered/fluxgo/pkg/toolkit"
)

var _ flux.Filter = new(CaptchaFilter)

const (
	FilterIdCaptcha = "captcha_filter"

	FeatureCaptcha = "feature:captcha"
)

type CaptchaConfig struct {
	FeatureAttr string
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
		FeatureAttr: FeatureCaptcha,
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
		attr, ok := ctx.Endpoint().AttributeEx(c.config.FeatureAttr)
		if !ok {
			return next(ctx)
		}
		idscope, idkey := c.config.LookupScope, c.config.IdKey
		valscope, valkey := c.config.LookupScope, c.config.ValueKey
		// 尝试解析自定义Id和Value
		// TODO 考虑缓存解析结果；但要注意动态变更Attr的情况：
		//  使用Map缓存，对比Attr的hash是否变更；
		for _, item := range attr.GetStrings() {
			onkey, expr, ok := toolkit.ParseDefineExpr(item)
			if !ok {
				continue
			}
			scope, key, ok := toolkit.ParseScopeExpr(expr)
			if !ok {
				continue
			}
			switch strings.ToLower(onkey) {
			case "id":
				idscope, idkey = scope, key
			case "value":
				valscope, valkey = scope, key
			}
		}
		id, value := common.LookupWebValue(ctx, idscope, idkey), common.LookupWebValue(ctx, valscope, valkey)
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
			Message:    "SERVER:CAPTCHA/value:not-match",
		}
	}
}
