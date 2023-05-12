package request3

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var ContentTypeKey = "Content-Type"

// Load certificate files with PEM format
func LoadCerts(certFile, keyFile string) ([]tls.Certificate, error) {
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return certs, nil
}

// NewTransport new http2 transport. For http client, please skip targetHostPem,myCert.
func NewTransport(targetHostPem []byte, myCerts []tls.Certificate, skipVerify bool) *http.Transport {
	pool := x509.NewCertPool()
	if targetHostPem != nil {
		pool.AppendCertsFromPEM(targetHostPem)
	}
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       myCerts,
			RootCAs:            pool,
			InsecureSkipVerify: skipVerify,
		},
	}

}

// NewTransport3 new http3 transport with Quic
func NewTransport3(targetHostPem []byte, myCerts []tls.Certificate, skipVerify bool) *http3.RoundTripper {
	pool := x509.NewCertPool()
	if targetHostPem != nil {
		pool.AppendCertsFromPEM(targetHostPem)
	}
	var qconf quic.Config
	return &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			Certificates:       myCerts,
			RootCAs:            pool,
			InsecureSkipVerify: skipVerify,
		},
		QuicConfig: &qconf,
	}
}

type Response struct {
	*http.Response
	bytes []byte
}

func (s *Response) Bytes() []byte {
	return s.bytes
}

func (s *Response) Text() string {
	return string(s.bytes)
}
func (s *Response) Json(v interface{}) error {
	return json.Unmarshal(s.bytes, v)
}

type Client struct {
	options   Options
	transport http.RoundTripper
	client    *http.Client
	cookies   []*http.Cookie
	headers   map[string]string
}

type Options struct {
	TargetHostPem []byte
	MyCerts       []tls.Certificate
	SkipVerify    bool
	Headers       map[string]string
	Cookies       []*http.Cookie
	Http3         bool
	Timeout       time.Duration
}

func NewClient(options Options) *Client {
	var transport http.RoundTripper
	if options.Http3 {
		transport = NewTransport3(options.TargetHostPem, options.MyCerts, options.SkipVerify)
	} else {
		transport = NewTransport(options.TargetHostPem, options.MyCerts, options.SkipVerify)
	}
	return &Client{
		options:   options,
		transport: transport,
		client: &http.Client{
			Timeout:   options.Timeout,
			Transport: transport,
		},
		headers: options.Headers,
		cookies: options.Cookies,
	}
}

type Closeable interface {
	Close() error
}

func (s *Client) Close() error {
	if c, ok := s.client.Transport.(Closeable); ok {
		return c.Close()
	}
	return nil
}
func (s *Client) Cookies() []*http.Cookie {
	return s.cookies
}
func (s *Client) Headers() map[string]string {
	return s.headers
}
func (s *Client) Client() *http.Client {
	return s.client
}
func (s *Client) Options() Options {
	return s.options
}
func (s *Client) Transport() http.RoundTripper {
	return s.transport
}
func (s *Client) SetTransport(transport http.RoundTripper) *Client {
	s.transport = transport
	return s
}
func (s *Client) SetCookies(cookies []*http.Cookie) *Client {
	s.cookies = cookies
	return s
}
func (s *Client) AppendCookie(cookie *http.Cookie) *Client {
	s.cookies = append(s.cookies, cookie)
	return s
}

func (s *Client) SetHeaders(headers map[string]string) *Client {
	s.headers = headers
	return s
}

func (s *Client) SetHeader(name, value string) *Client {
	if s.headers == nil {
		s.headers = map[string]string{name: value}
	} else {
		s.headers[name] = value
	}
	return s
}

func (s *Client) Request(method, url string, urlQuery map[string]string, body io.Reader) (*Response, error) {
	url, err := mergeQuery(url, urlQuery)
	if err != nil {
		return nil, err
	}

	req, err := makeRequest(strings.ToUpper(method), url, body, s.headers)
	if err != nil {
		return nil, err
	}
	if t, ok := s.transport.(*http3.RoundTripper); ok {
		t.TLSClientConfig.ServerName = req.URL.Hostname()
		req.Proto = "HTTP/3"
	}
	if s.cookies != nil {
		s.client.Jar.SetCookies(req.URL, s.cookies)
	}
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return &Response{Response: res, bytes: bytes}, nil
}
func (s *Client) PostJSON(uri string, query map[string]string, data interface{}) (*Response, error) {
	s.SetHeader(ContentTypeKey, "application/json")
	bs, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	body := bytes.NewBuffer(bs)
	return s.Request("POST", uri, query, body)
}

type UploadFile struct {
	Filename string
	Field    string
	Content  io.Reader
}

func (s *Client) PostForm(uri string, query, form map[string]string, files []UploadFile) (*Response, error) {
	var body io.Reader
	contentType := "application/x-www-form-urlencoded"
	var err error
	if files == nil {
		data := make(map[string][]string)
		for k, v := range form {
			data[k] = []string{v}
		}
		body = strings.NewReader(url.Values(data).Encode())
	} else {
		body, contentType, err = makeForm(form, files)
		if err != nil {
			return nil, err
		}
	}
	s.SetHeader(ContentTypeKey, contentType)
	return s.Request("POST", uri, query, body)

}

func (s *Client) Get(uri string, query, header map[string]string) (*Response, error) {
	return s.Request("GET", uri, query, nil)
}

func makeRequest(method, uri string, body io.Reader, header map[string]string) (*http.Request, error) {
	req, err := http.NewRequest(method, uri, body)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return req, nil
}

func mergeQuery(uri string, query map[string]string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return uri, err
	}
	q := u.Query()
	for k, v := range query {
		q.Add(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func makeForm(form map[string]string, files []UploadFile) (io.Reader, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for k, v := range form {
		writer.WriteField(k, v)
	}
	for _, file := range files {
		part, err := writer.CreateFormFile(file.Field, file.Filename)
		if err != nil {
			return nil, "", err
		}
		_, err = io.Copy(part, file.Content)
		if err != nil {
			return nil, "", err
		}
	}
	err := writer.Close()
	if err != nil {
		return nil, "", err
	}
	return body, writer.FormDataContentType(), nil
}
