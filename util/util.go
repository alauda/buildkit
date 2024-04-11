package util

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/moby/buildkit/util/tracing"
)

func DefaultInsecureClient() *http.Client {
	tc := &tls.Config{}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		MaxIdleConns:          30,
		IdleConnTimeout:       120 * time.Second,
		MaxIdleConnsPerHost:   4,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
		TLSNextProto:          make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
	}

	tc.InsecureSkipVerify = true
	transport.TLSClientConfig = tc

	return &http.Client{
		Transport: tracing.NewTransport(transport),
	}
}
