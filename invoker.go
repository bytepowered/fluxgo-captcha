package captcha

import (
	"encoding/base64"
	"github.com/bytepowered/flux"
	"github.com/bytepowered/flux/transporter/inapp"
	"github.com/dchest/captcha"
	"github.com/valyala/bytebufferpool"
	"strings"
)

type InvokeConfig struct {
	NumberLen   int
	ImageWidth  int
	ImageHeight int
}

var DefaultConfig = InvokeConfig{
	NumberLen:   5,
	ImageWidth:  120,
	ImageHeight: 80,
}

// NewGenerateIdInvokeFunc 创建生成验证码ID的InvokeFunc
func NewGenerateIdInvokeFunc(cc InvokeConfig) inapp.InvokeFunc {
	return func(ctx *flux.Context, service flux.Service) (interface{}, *flux.ServeError) {
		return map[string]interface{}{
			"id":     captcha.NewLen(cc.NumberLen),
			"srvtag": "captcha/id",
		}, nil
	}
}

// NewImageInvokeFunc 创建获取图形验证码图片的InvokeFunc
func NewImageInvokeFunc(cc InvokeConfig) inapp.InvokeFunc {
	return func(ctx *flux.Context, service flux.Service) (interface{}, *flux.ServeError) {
		id := ctx.QueryVar("id")
		if id == "" {
			return nil, &flux.ServeError{
				StatusCode: flux.StatusBadRequest,
				ErrorCode:  "SERVER:CAPTCHA:VERIFY",
				Message:    "SERVER:CAPTCHA/id-notfound",
			}
		}
		reload := strings.EqualFold("true", ctx.QueryVar("reload"))
		if reload && !captcha.Reload(id) {
			return nil, &flux.ServeError{
				StatusCode: flux.StatusBadRequest,
				ErrorCode:  "SERVER:CAPTCHA:RELOAD",
				Message:    "SERVER:CAPTCHA/id-notfound",
			}
		}
		return makeCaptchaImage(ctx, &cc, id)
	}
}

func makeCaptchaImage(ctx *flux.Context, cc *InvokeConfig, id string) (interface{}, *flux.ServeError) {
	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)
	err := captcha.WriteImage(buf, id, cc.ImageWidth, cc.ImageHeight)
	if err == captcha.ErrNotFound {
		return nil, &flux.ServeError{
			StatusCode: flux.StatusBadRequest,
			ErrorCode:  "SERVER:CAPTCHA:VERIFY",
			Message:    "SERVER:CAPTCHA/id-invalid",
		}
	}
	if err != nil {
		return nil, &flux.ServeError{
			StatusCode: flux.StatusServerError,
			ErrorCode:  flux.ErrorCodeGatewayInternal,
			Message:    "SERVER:CAPTCHA:RENDERER/image",
			CauseError: err,
		}
	}
	// 输出PNG图片
	if strings.EqualFold("png", ctx.QueryVar("format")) {
		ctx.ResponseWriter().Header().Set(flux.HeaderContentType, "image/png")
		return buf.Bytes(), nil
	}
	// 输出Base64
	return map[string]interface{}{
		"id":     id,
		"encode": "data:image/png;base64",
		"image":  base64.StdEncoding.EncodeToString(buf.Bytes()),
		"width":  cc.ImageWidth, "height": cc.ImageHeight,
		"srvtag": "captcha/image",
	}, nil
}
