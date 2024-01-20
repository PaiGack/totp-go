package totp

import "testing"

func TestTotp(t *testing.T) {
	// ref: https://www.lzltool.cn/Tools/Base32Encode
	// 编码后去掉 =
	const testSecret = "PMRHKIR2GEZDGNBVGYWCE4BCHIYTEMZUGU3CYITEEI5DCMRTGQ2TM7I" //base32-no-padding-encoded-string

	g := NewGA2FaSha1(
		testSecret,
		6,
		30,
	)
	totp, err := g.Code()
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(totp)
}

func TestQr(t *testing.T) {
	const testSecret = "PMRHKIR2GEZDGNBVGYWCE4BCHIYTEMZUGU3CYITEEI5DCMRTGQ2TM7I" //base32-no-padding-encoded-string

	g := NewGA2FaSha1(
		testSecret,
		6,
		30,
	)

	qrString := g.QrString("Pai2:totp", "Pai2.hz")
	t.Log(qrString)
}
