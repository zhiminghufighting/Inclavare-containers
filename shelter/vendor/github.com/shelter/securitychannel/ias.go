package remoteattestation

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	//pb "github.com/inclavare-containers/rune/libenclave/attestation/proto"
	//"github.com/inclavare-containers/rune/libenclave/intelsgx"
	"github.com/sirupsen/logrus"
	"io"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"unsafe"
)

const (
	SigStructLength       = 1808
	EinittokenLength      = 304
	TargetinfoLength      = 512
	ReportLength          = ReportBodyLength + 48
	ReportBodyLength      = 384
	QuoteLength           = QuoteBodyLength + ReportBodyLength + 4
	QuoteBodyLength       = 48
	NonceLength           = 16
	SpidLength            = 16
	SubscriptionKeyLength = 16
	SgxMaxQuoteLength     = 2048
)

type SigStruct struct {
	Header         [16]byte  `struct:"[16]byte"`
	Vendor         uint32    `struct:"uint32,little"`
	BuildYear      uint16    `struct:"uint16,little"`
	BuildMonth     uint8     `struct:"uint8"`
	BuildDay       uint8     `struct:"uint8"`
	Header2        [16]byte  `struct:"[16]byte"`
	SwDefined      uint32    `struct:"uint32,little"`
	_              [84]byte  `struct:"[84]byte"`
	Modulus        [384]byte `struct:"[384]byte"`
	Exponent       uint32    `struct:"uint32,little"`
	Signature      [384]byte `struct:"[384]byte"`
	MiscSelect     uint32    `struct:"uint32,little"`
	MiscMask       uint32    `struct:"uint32,little"`
	_              [4]byte   `struct:"[4]byte"`
	ISVFamilyId    [16]byte  `struct:"[16]byte"`
	Attributes     [16]byte  `struct:"[16]byte"`
	AttributesMask [16]byte  `struct:"[16]byte"`
	EnclaveHash    [32]byte  `struct:"[32]byte"`
	_              [16]byte  `struct:"[16]byte"`
	ISVExtProdId   [16]byte  `struct:"[16]byte"`
	ISVProdId      uint16    `struct:"uint16,little"`
	ISVSvn         uint16    `struct:"uint16,little"`
	_              [12]byte  `struct:"[12]byte"`
	Q1             [384]byte `struct:"[384]byte"`
	Q2             [384]byte `struct:"[384]byte"`
}

type Einittoken struct {
	Valid              uint32   `struct:"uint32,little"`
	_                  [44]byte `struct:"[44]byte"`
	Attributes         [16]byte `struct:"[16]byte"`
	MrEnclave          [32]byte `struct:"[32]byte"`
	_                  [32]byte `struct:"[32]byte"`
	MrSigner           [32]byte `struct:"[32]byte"`
	_                  [32]byte `struct:"[32]byte"`
	CpuSvnLe           [16]byte `struct:"[16]byte"`
	ISVProdIdLe        uint16   `struct:"uint16"`
	ISVSvnLe           uint16   `struct:"uint16"`
	_                  [24]byte `struct:"[24]byte"`
	MaskedMiscSelectLe uint32   `struct:"uint32"`
	MaskedAttributesLe [16]byte `struct:"[16]byte"`
	KeyId              [32]byte `struct:"[32]byte"`
	Mac                [16]byte `struct:"[16]byte"`
}


type Targetinfo struct {
	Measurement   [32]byte  `struct:"[32]byte"`
	Attributes    [16]byte  `struct:"[16]byte"`
	CetAttributes uint8     `struct:"uint8"`
	_             uint8     `struct:"uint8"`
	ConfigSvn     uint16    `struct:"uint16"`
	MiscSelect    uint32    `struct:"uint32"`
	_             [8]byte   `struct:"[8]byte"`
	ConfigId      [64]byte  `struct:"[64]byte"`
	_             [384]byte `struct:"[384]byte"`
}


type Report struct {
	ReportBody
	Keyid [32]byte `struct:"[32]byte"`
	Mac   [16]byte `struct:"[16]byte"`
}


type ReportBody struct {
	CpuSvn       [16]byte `struct:"[16]byte"`
	MiscSelect   uint32   `struct:"uint32"`
	_            [12]byte `struct:"[12]byte"`
	IsvExtProdId [16]byte `struct:"[16]byte"`
	Attributes   [16]byte `struct:"[16]byte"`
	MrEnclave    [32]byte `struct:"[32]byte"`
	_            [32]byte `struct:"[32]byte"`
	MrSigner     [32]byte `struct:"[32]byte"`
	_            [32]byte `struct:"[32]byte"`
	ConfigId     [64]byte `struct:"[64]byte"`
	IsvProdId    uint16   `struct:"uint16"`
	IsvSvn       uint16   `struct:"uint16"`
	ConfigSvn    uint16   `struct:"uint16"`
	_            [42]byte `struct:"[42]byte"`
	IsvFamilyId  [16]byte `struct:"[16]byte"`
	ReportData   [64]byte `struct:"[64]byte"`
}

type Quote struct {
	QuoteBody
	ReportBody
	SigLen uint32 `struct:"uint32"`
}

const (
	QuoteSignatureTypeUnlinkable = iota
	QuoteSignatureTypeLinkable
	InvalidQuoteSignatureType
)

const (
	QuoteVersion = 2
)

type QuoteBody struct {
	Version       uint16   `struct:"uint16"`
	SignatureType uint16   `struct:"uint16"`
	Gid           uint32   `struct:"uint32"`
	ISVSvnQe      uint16   `struct:"uint16"`
	ISVSvnPce     uint16   `struct:"uint16"`
	_             [4]byte  `struct:"[4]byte"`
	Basename      [32]byte `struct:"[32]byte"`
}

const (
	spidLength            = 16
	subscriptionKeyLength = 16
)

type IasAttestation struct {
	reportApiUrl    string
	spid            [spidLength]byte
	subscriptionKey [subscriptionKeyLength]byte
}

type IasReportStatus struct {
	RequestId   string
	ReportId    string
	Timestamp   string
	QuoteStatus string
}

const (
	apiV3 = 3
	apiV4 = 4
)

var (
	apiVersion uint64 = apiV4
)

type evidencePayload struct {
	IsvEnclaveQuote string `json:"isvEnclaveQuote"`
	PseManifest     string `json:"pseManifest,omitempty"`
	Nonce           string `json:"nonce,omitempty"`
}

type verificationReport struct {
	Id                    string `json:"id"`
	Timestamp             string `json:"timestamp"`
	Version               uint32 `json:"version"`
	IsvEnclaveQuoteStatus string `json:"isvEnclaveQuoteStatus"`
	IsvEnclaveQuoteBody   string `json:"isvEnclaveQuoteBody"`
	RevocationReason      uint32 `json:"revocationReason,omitempty"`
	PseManifestStatus     string `json:"pseManifestStatus,omitempty"`
	PseManifestHash       string `json:"pseManifestHash,omitempty"`
	PlatformInfoBlob      string `json:"platformInfoBlob,omitempty"`
	Nonce                 string `json:"nonce,omitempty"`
	EpidPseudonym         string `json:"epidPseudonym,omitempty"`
	// V4 fields
	AdvisoryIds string   `json:"advisoryURL,omitempty"`
	AdvisoryUrl []string `json:"advisoryIDs,omitempty"`
}


func NewIasAttestation(cfg map[string]string) (*IasAttestation, error) {
	isProduct := false
	v, ok := cfg["service-class"]
	if ok && v == "product" {
		isProduct = true
	}

	spid, ok := cfg["spid"]
	if !ok || spid == "" {
		return nil, fmt.Errorf("EPID parameter spid not specified")
	}

	if len(spid) != spidLength*2 {
		return nil, fmt.Errorf("Spid must be %d-character long", spidLength*2)
	}

	subKey, ok := cfg["subscription-key"]
	if !ok && subKey == "" {
		return nil, fmt.Errorf("EPID parameter subscription-key not specified")
	}

	if len(subKey) != subscriptionKeyLength*2 {
		return nil, fmt.Errorf("Subscription key must be %d-character long",
			subscriptionKeyLength*2)
	}

	var rawSubKey []byte
	var err error
	if rawSubKey, err = hex.DecodeString(subKey); err != nil {
		return nil, fmt.Errorf("Failed to decode subscription key: %s", err)
	}

	var rawSpid []byte
	if rawSpid, err = hex.DecodeString(spid); err != nil {
		return nil, fmt.Errorf("Failed to decode spid: %s", err)
	}

	url := "https://api.trustedservices.intel.com/sgx"
	if !isProduct {
		url += "/dev"
	}

	version := apiVersion
	apiVer, ok := cfg["apiVer"]
	if ok && apiVer != "" {
		version, err = strconv.ParseUint(apiVer, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("Invalid IAS API Version: %s", err)
		}
		if version != apiV3 && apiVersion != apiV4 {
			return nil, fmt.Errorf("Unsupported IAS API Version: %s", apiVer)
		}
	}
	url += fmt.Sprintf("/attestation/v%d/report", version)

	ias := &IasAttestation{
		reportApiUrl: url,
	}
	copy(ias.subscriptionKey[:], rawSubKey)
	copy(ias.spid[:], rawSpid)
	return ias, nil
}


func (ias *IasAttestation) CheckQuote(q []byte) error {
	quote := (*Quote)(unsafe.Pointer(&q[0]))
	logrus.Debugf("Target Platform's Quote")
	logrus.Debugf("  Quote Body")
	logrus.Debugf("    QUOTE Structure Version:                               %d",
		quote.Version)
	logrus.Debugf("    EPID Signature Type:                                   %d",
		quote.SignatureType)
	logrus.Debugf("    Platform's EPID Group ID:                              %#08x",
		quote.Gid)
	logrus.Debugf("    Quoting Enclave's ISV assigned SVN:                    %#04x",
		quote.ISVSvnQe)
	logrus.Debugf("    Provisioning Certification Enclave's ISV assigned SVN: %#04x",
		quote.ISVSvnPce)
	logrus.Debugf("    EPID Basename:                                         0x%v",
		hex.EncodeToString(quote.Basename[:]))
	logrus.Debugf("  Report Body")
	logrus.Debugf("    Target CPU SVN:                                        0x%v",
		hex.EncodeToString(quote.CpuSvn[:]))
	logrus.Debugf("    Enclave Misc Select:                                   %#08x",
		quote.MiscSelect)
	logrus.Debugf("    Enclave Attributes:                                    0x%v",
		hex.EncodeToString(quote.Attributes[:]))
	logrus.Debugf("    Enclave Hash:                                          0x%v",
		hex.EncodeToString(quote.MrEnclave[:]))
	logrus.Debugf("    Enclave Signer:                                        0x%v",
		hex.EncodeToString(quote.MrSigner[:]))
	logrus.Debugf("    ISV assigned Product ID:                               %#04x",
		quote.IsvProdId)
	logrus.Debugf("    ISV assigned SVN:                                      %#04x",
		quote.IsvSvn)
	logrus.Debugf("    Report Data:                                           0x%v...",
		hex.EncodeToString(quote.ReportData[:32]))
	logrus.Debugf("  Encrypted EPID Signature")
	logrus.Debugf("    Length:                                                %d",
		quote.SigLen)
	logrus.Debugf("    Signature:                                             0x%v...",
		hex.EncodeToString(q[QuoteLength:QuoteLength+32]))

	if quote.Version != QuoteVersion {
		return fmt.Errorf("Invalid quote version: %d", quote.Version)
	}

	if quote.SignatureType != QuoteSignatureTypeUnlinkable &&
		quote.SignatureType != QuoteSignatureTypeLinkable {
		return fmt.Errorf("Invalid signature type: %#04x", quote.SignatureType)
	}

	spid := [spidLength]byte{}
	copy(spid[:], quote.Basename[:spidLength])
	if spid != ias.spid {
		return fmt.Errorf("Invalid spid in quote body: 0x%v",
			hex.EncodeToString(quote.Basename[:]))
	}
	return nil
}

func (ias *IasAttestation) VerifyQuote(quote []byte) (*IasReportStatus, error) {
	status, _, err := ias.RetrieveIasReport(quote, 0)
	if err != nil {
		return nil, err
	}
	return status, nil
}

func (ias *IasAttestation) GetVerifiedReport(quote []byte, nonce uint64) (*IasReportStatus, map[string]string, error) {
	return ias.RetrieveIasReport(quote, nonce)
}

func (ias *IasAttestation) RetrieveIasReport(quote []byte, nonce uint64) (*IasReportStatus, map[string]string, error) {
	var nonceStr string
	if nonce == 0 {
		nonceStr = strconv.FormatUint(rand.Uint64(), 16) + strconv.FormatUint(rand.Uint64(), 16)
	} else {
		nonceStr = strconv.FormatUint(nonce, 16)
	}

	p := &evidencePayload{
		IsvEnclaveQuote: base64.StdEncoding.EncodeToString(quote),
		PseManifest:     "",
		Nonce:           nonceStr,
	}

	resp, err := ias.reportAttestationEvidence(p)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	status, rawReport, err := checkAttestationVerificationReport(resp, quote, nonceStr)
	if err != nil {
		return nil, nil, err
	}
	return status, formatIasReport(resp, rawReport), nil
}



func (ias *IasAttestation) reportAttestationEvidence(p *evidencePayload) (*http.Response, error) {
	var jp []byte
	var err error

	if jp, err = json.Marshal(p); err != nil {
		return nil, fmt.Errorf("Failed to marshal evidence payload: %s", err)
	}

	bjp := bytes.NewBuffer(jp)
	var req *http.Request
	if req, err = http.NewRequest(http.MethodPost, ias.reportApiUrl, bjp); err != nil {
		return nil, fmt.Errorf("Failed to create http.Request: %s", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Ocp-Apim-Subscription-Key", hex.EncodeToString(ias.subscriptionKey[:]))
	logrus.Debugf("Initializing attestation evidence report ...")
	if dump, err := httputil.DumpRequestOut(req, true); err == nil {
		logrus.Debugf("--- start of request ---")
		logrus.Debugf("%s\n", dump)
		logrus.Debugf("--- end of request ---")
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return nil, fmt.Errorf("Failed to send http request and receive http response: %s", err)
	}

	logrus.Debugf("Attestation evidence response retrieved ...")
	if dump, err := httputil.DumpResponse(resp, true); err == nil {
		logrus.Debugf("--- start of response ---")
		logrus.Debugf("%s\n", dump)
		logrus.Debugf("--- end of response ---")
	}
	return resp, nil
}



func formatIasReport(resp *http.Response, rawReport string) map[string]string {
	iasReport := make(map[string]string)
	iasReport["Body"] = rawReport
	iasReport["StatusCode"] = strconv.FormatUint(uint64(resp.StatusCode), 10)
	iasReport["Request-ID"] = resp.Header.Get("Request-ID")
	iasReport["X-Iasreport-Signature"] = resp.Header.Get("X-Iasreport-Signature")
	iasReport["X-Iasreport-Signing-Certificate"] = resp.Header.Get("X-Iasreport-Signing-Certificate")
	iasReport["ContentLength"] = strconv.FormatUint(uint64(resp.ContentLength), 10)
	iasReport["Content-Type"] = resp.Header.Get("Content-Type")
	return iasReport
}



func checkAttestationVerificationReport(resp *http.Response, quote []byte, nonce string) (*IasReportStatus, string, error) {
	status := &IasReportStatus{
		RequestId:   "",
		ReportId:    "",
		QuoteStatus: "",
	}

	if resp.StatusCode != 200 {
		errMsg := "Unexpected status"
		switch resp.StatusCode {
		case 400:
			errMsg = "Invalid Attestation Evidence Payload. The client should not repeat the request without modifications."
		case 401:
			errMsg = "Failed to authenticate or authorize request."
		case 500:
			errMsg = "Internal error occurred."
		case 503:
			errMsg = "IAS is currently not able to process the request due to a temporary overloading or maintenance. This is a temporary state and the same request can be repeated after some time."
		default:
		}
		return status, "", fmt.Errorf("%s: %s", resp.Status, errMsg)
	}

	reqId := resp.Header.Get("Request-ID")
	if reqId == "" {
		return status, "", fmt.Errorf("No Request-ID in response header")
	}
	status.RequestId = reqId

	if resp.Header.Get("X-Iasreport-Signature") == "" {
		return status, "", fmt.Errorf("No X-Iasreport-Signature in response header")
	}

	if resp.Header.Get("X-Iasreport-Signing-Certificate") == "" {
		return status, "", fmt.Errorf("No X-Iasreport-Signing-Certificate in response header")
	}
	if resp.ContentLength == -1 {
		return status, "", fmt.Errorf("Unknown length of response body")
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		return status, "", fmt.Errorf("Invalid content type (%s) in response",
			resp.Header.Get("Content-Type"))
	}

	var err error
	rawReport := make([]byte, resp.ContentLength)
	if _, err = io.ReadFull(resp.Body, rawReport); err != nil {
		return status, "", fmt.Errorf("Failed to read reponse body (%d-byte): %s",
			resp.ContentLength, err)
	}

	var report verificationReport
	if err = json.Unmarshal(rawReport, &report); err != nil {
		return status, "", fmt.Errorf("Failed to unmarshal attestation verification report: %s: %s",
			rawReport, err)
	}

	status.ReportId = report.Id
	status.Timestamp = report.Timestamp
	status.QuoteStatus = report.IsvEnclaveQuoteStatus

	if report.Version != (uint32)(apiVersion) {
		return status, "", fmt.Errorf("Unsupported attestation API version %d in attesation verification report",
			report.Version)
	}

	if report.Nonce != nonce {
		return status, "", fmt.Errorf("Invalid nonce in attestation verification report: %s",
			report.Nonce)
	}

	if report.Id == "" || report.Timestamp == "" ||
		report.IsvEnclaveQuoteStatus == "" ||
		report.IsvEnclaveQuoteBody == "" {
		return status, "", fmt.Errorf("Required fields in attestation verification report is not present: %s",
			string(rawReport))
	}

	if report.IsvEnclaveQuoteStatus == "GROUP_OUT_OF_DATE" ||
		report.IsvEnclaveQuoteStatus == "CONFIGURATION_NEEDED" {
		if report.Version == apiV3 {
			if resp.Header.Get("Advisory-Ids") == "" || resp.Header.Get("Advisory-Url") == "" {
				return status, "", fmt.Errorf("Advisory-Ids or Advisory-Url is not present in response header")
			}
		} else if report.Version == apiV4 && (report.AdvisoryIds == "" || report.AdvisoryUrl == nil) {
			return status, "", fmt.Errorf("Advisory-Ids or Advisory-Url is not present in attestation verification report")
		}
	}

	var quoteBody []byte
	if quoteBody, err = base64.StdEncoding.DecodeString(report.IsvEnclaveQuoteBody); err != nil {
		return status, "", fmt.Errorf("Invalid isvEnclaveQuoteBody: %s",
			report.IsvEnclaveQuoteBody)
	}

	if len(quoteBody) != QuoteBodyLength+ReportBodyLength {
		return status, "", fmt.Errorf("Invalid length of isvEnclaveQuoteBody: %d-byte",
			len(quoteBody))
	}

	for i, v := range quoteBody {
		if v != quote[i] {
			return status, "", fmt.Errorf("Unexpected isvEnclaveQuoteBody: %s",
				report.IsvEnclaveQuoteBody)
		}
	}

	var sig []byte
	if sig, err = base64.StdEncoding.DecodeString(
		resp.Header.Get("X-Iasreport-Signature")); err != nil {
		return status, "", fmt.Errorf("Invalid X-Iasreport-Signature in response header: %s",
			resp.Header.Get("X-Iasreport-Signature"))
	}

	var pemCerts string
	if pemCerts, err = url.QueryUnescape(
		resp.Header.Get("X-Iasreport-Signing-Certificate")); err != nil {
		return status, "", fmt.Errorf("Failed to unescape X-Iasreport-Signing-Certificate in response header: %s: %s",
			resp.Header.Get("X-Iasreport-Signing-Certificate"), err)
	}

	rawPemCerts := []byte(pemCerts)
	rawPemCerts = append(rawPemCerts, caCert...)
	var derCerts []byte
	for true {
		var b *pem.Block
		if b, rawPemCerts = pem.Decode(rawPemCerts); err != nil {
			return status, "", fmt.Errorf("Failed to convert PEM certificate to DER format: %s: %s",
				pemCerts, err)
		}
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return status, "", fmt.Errorf("Returned content is not PEM certificate: %s",
				b.Type)
		}
		derCerts = append(derCerts, b.Bytes...)
	}

	var x509Certs []*x509.Certificate
	if x509Certs, err = x509.ParseCertificates(derCerts); err != nil {
		return status, "", fmt.Errorf("Failed to parse certificates: %s", err)
	}

	cert := x509Certs[0]
	if err = cert.CheckSignature(x509.SHA256WithRSA, rawReport, sig); err != nil {
		return status, "", fmt.Errorf("Failed to verify the attestation verification report: %s",
			err)
	}

	for _, parentCert := range x509Certs[1:] {
		if err = cert.CheckSignatureFrom(parentCert); err != nil {
			return status, "", fmt.Errorf("Failed to verify the certificate (%s) with parent certificate (%s): %s",
				cert.Subject.String(), parentCert.Subject.String(), err)
		}
		cert = parentCert
	}
	return status, string(rawReport), nil
}