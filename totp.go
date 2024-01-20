package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// GA2FaSha1 只实现google authenticator sha1
type GA2FaSha1 struct {
	secret string // The Secret parameter is an arbitrary key value encoded in Base32 according to RFC 3548. The padding specified in RFC 3548 section 2.2 is not required and should be omitted.
	digits int    // 数字数量
	expire uint64 // 更新周期单位秒

	totpFormat string
}

func NewGA2FaSha1(secret string, digits int, expire uint64) GA2FaSha1 {
	return GA2FaSha1{
		secret: secret,
		digits: digits,
		expire: expire,

		totpFormat: fmt.Sprintf("%%0%dd", digits), //数字长度补零,
	}
}

// QrString google authenticator 扫描二维码的二维码字符串
// 规范文档 https://github.com/google/google-authenticator/wiki/Key-Uri-Format
func (m *GA2FaSha1) QrString(label, issuer string) string {
	issuer = url.QueryEscape(label) //有一些小程序MFA不支持
	return fmt.Sprintf(`otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d`, label, m.secret, issuer, m.digits, m.expire)
}

// Code 计算 Time-based One-time Password 数字
func (m *GA2FaSha1) Code() (string, error) {
	count := uint64(time.Now().Unix()) / m.expire
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(m.secret)
	if err != nil {
		return "", errors.New("https://github.com/google/google-authenticator/wiki/Key-Uri-Format,REQUIRED: The base32NoPaddingEncodedSecret parameter is an arbitrary key value encoded in Base32 according to RFC 3548. The padding specified in RFC 3548 section 2.2 is not required and should be omitted.")
	}

	hVal, err := hotp(key, count, m.digits)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(m.totpFormat, hVal), nil
}

func (m *GA2FaSha1) Verify(code string) (bool, error) {
	if len(code) != m.digits {
		return false, nil
	}

	mCode, err := m.Code()
	if err != nil {
		return false, err
	}

	return mCode == code, nil
}

// RFC 6238
// 只支持sha1
func hotp(key []byte, counter uint64, digits int) (int, error) {
	h := hmac.New(sha1.New, key)
	err := binary.Write(h, binary.BigEndian, counter)
	if err != nil {
		return 0, err
	}

	sum := h.Sum(nil)
	// 取 sha1 的最后 4 byte
	// 	0x7FFFFFFF 是long int的最大值
	// 	math.MaxUint32 == 2^32-1
	// 	& 0x7FFFFFFF == 2^31  Set the first bit of truncatedHash to zero  //remove the most significant bit
	// 	len(sum)-1]&0x0F 最后 像登陆 (bytes.len-4)
	// 	取sha1 bytes的最后4byte 转换成 uint32
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	//	取十进制的余数
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d), nil
}
