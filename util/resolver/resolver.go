package resolver

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/containerd/remotes/docker"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/docker/registry"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/resolver/config"
	"github.com/moby/buildkit/util/tracing"
	"github.com/moby/buildkit/version"
	"github.com/pkg/errors"
)

const (
	defaultPath = "/v2"

	// DefaultRegistryVersionHeader is the name of the default HTTP header
	// that carries Registry version info
	DefaultRegistryVersionHeader = "Docker-Distribution-Api-Version"
)

func fillInsecureOpts(host string, c config.RegistryConfig, h docker.RegistryHost) (*docker.RegistryHost, error) {
	tc, err := loadTLSConfig(c)
	if err != nil {
		return nil, err
	}
	var isHTTP bool

	if c.PlainHTTP != nil && *c.PlainHTTP {
		isHTTP = true
	}
	if c.PlainHTTP == nil {
		if ok, _ := docker.MatchLocalhost(host); ok {
			isHTTP = true
		}
	}

	httpsTransport := newDefaultTransport()
	httpsTransport.TLSClientConfig = tc

	if c.Insecure != nil && *c.Insecure {
		h2 := h

		var transport http.RoundTripper = httpsTransport
		if isHTTP {
			transport = &httpFallback{super: transport}
		}
		h2.Client = &http.Client{
			Transport: tracing.NewTransport(transport),
		}
		tc.InsecureSkipVerify = true
		return &h2, nil
	} else if isHTTP {
		h2 := h
		h2.Scheme = "http"
		return &h2, nil
	}

	h.Client = &http.Client{
		Transport: tracing.NewTransport(httpsTransport),
	}
	return &h, nil
}

func loadTLSConfig(c config.RegistryConfig) (*tls.Config, error) {
	for _, d := range c.TLSConfigDir {
		fs, err := os.ReadDir(d)
		if err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, os.ErrPermission) {
			return nil, errors.WithStack(err)
		}
		for _, f := range fs {
			if strings.HasSuffix(f.Name(), ".crt") {
				c.RootCAs = append(c.RootCAs, filepath.Join(d, f.Name()))
			}
			if strings.HasSuffix(f.Name(), ".cert") {
				c.KeyPairs = append(c.KeyPairs, config.TLSKeyPair{
					Certificate: filepath.Join(d, f.Name()),
					Key:         filepath.Join(d, strings.TrimSuffix(f.Name(), ".cert")+".key"),
				})
			}
		}
	}

	tc := &tls.Config{}
	if len(c.RootCAs) > 0 {
		systemPool, err := x509.SystemCertPool()
		if err != nil {
			if runtime.GOOS == "windows" {
				systemPool = x509.NewCertPool()
			} else {
				return nil, errors.Wrapf(err, "unable to get system cert pool")
			}
		}
		tc.RootCAs = systemPool
	}

	for _, p := range c.RootCAs {
		dt, err := os.ReadFile(p)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read %s", p)
		}
		tc.RootCAs.AppendCertsFromPEM(dt)
	}

	for _, kp := range c.KeyPairs {
		cert, err := tls.LoadX509KeyPair(kp.Certificate, kp.Key)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load keypair for %s", kp.Certificate)
		}
		tc.Certificates = append(tc.Certificates, cert)
	}
	return tc, nil
}

// NewRegistryConfig converts registry config to docker.RegistryHosts callback
func NewRegistryConfig(m map[string]config.RegistryConfig) docker.RegistryHosts {
	return docker.Registries(
		func(host string) ([]docker.RegistryHost, error) {
			c, ok := m[host]
			if !ok {
				return nil, nil
			}

			var out []docker.RegistryHost

			for _, rawMirror := range c.Mirrors {
				h := newMirrorRegistryHost(rawMirror)
				mirrorHost := h.Host
				host, err := fillInsecureOpts(mirrorHost, m[mirrorHost], h)
				if err != nil {
					return nil, err
				}

				out = append(out, *host)
			}

			if host == "docker.io" {
				host = "registry-1.docker.io"
			}

			h := docker.RegistryHost{
				Scheme:       "https",
				Client:       NewInsecureDefaultClient(),
				Host:         host,
				Path:         "/v2",
				Capabilities: docker.HostCapabilityPush | docker.HostCapabilityPull | docker.HostCapabilityResolve,
			}

			hosts, err := fillInsecureOpts(host, c, h)
			if err != nil {
				return nil, err
			}

			out = append(out, *hosts)

			return out, nil
		},
		docker.ConfigureDefaultRegistries(
			docker.WithClient(NewInsecureDefaultClient()),
			docker.WithPlainHTTP(isPlainHTTP),
		),
	)
}

func isPlainHTTP(host string) (bool, error) {
	plainHTTP, err := docker.MatchLocalhost(host)
	if err != nil {
		return false, err
	}

	if plainHTTP {
		return plainHTTP, nil
	}

	return isHttpRegistry(host), nil
}

func isHttpRegistry(host string) bool {
	base := newDefaultTransport()
	base.TLSClientConfig = &tls.Config{}
	base.TLSClientConfig.InsecureSkipVerify = true

	modifiers := registry.Headers(version.UserAgent(), nil)
	authTransport := transport.NewTransport(base, modifiers...)

	// By default, http attempts to authenticate the v2 interface.
	endpoint := &url.URL{
		Scheme: "https",
		Host:   host,
	}
	v2Version := auth.APIVersion{
		Type:    "registry",
		Version: "2.0",
	}

	pingClient := &http.Client{
		Transport: authTransport,
		Timeout:   15 * time.Second,
	}

	endpointStr := strings.TrimRight(endpoint.String(), "/") + "/v2/"
	req, err := http.NewRequest(http.MethodGet, endpointStr, nil)
	if err != nil {
		return true
	}

	resp, err := pingClient.Do(req)
	if err != nil {
		bklog.L.Debugf("failed request %s v2 endpoint response, error: %s", host, err.Error())
		return true
	}
	defer resp.Body.Close()

	versions := auth.APIVersions(resp, DefaultRegistryVersionHeader)
	bklog.L.Debugf("%s v2 endpoint response status code %d", host, resp.StatusCode)
	for _, pingVersion := range versions {
		if pingVersion == v2Version {
			// The version header indicates we're definitely
			// talking to a v2 registry. So don't allow future
			// fallbacks to the v1 protocol.
			bklog.L.Debugf("%s is https registry", host)
			return false
		}
	}

	return true
}

func newMirrorRegistryHost(mirror string) docker.RegistryHost {
	mirrorHost, mirrorPath := extractMirrorHostAndPath(mirror)
	path := path.Join(defaultPath, mirrorPath)
	h := docker.RegistryHost{
		Scheme:       "https",
		Client:       NewInsecureDefaultClient(),
		Host:         mirrorHost,
		Path:         path,
		Capabilities: docker.HostCapabilityPull | docker.HostCapabilityResolve,
	}

	return h
}

func NewInsecureDefaultClient() *http.Client {
	httpsTransport := newDefaultTransport()
	httpsTransport.TLSClientConfig = &tls.Config{}
	httpsTransport.TLSClientConfig.InsecureSkipVerify = true

	return &http.Client{
		Transport: tracing.NewTransport(httpsTransport),
	}
}

func newDefaultClient() *http.Client {
	return &http.Client{
		Transport: tracing.NewTransport(newDefaultTransport()),
	}
}

// newDefaultTransport is for pull or push client
//
// NOTE: For push, there must disable http2 for https because the flow control
// will limit data transfer. The net/http package doesn't provide http2 tunable
// settings which limits push performance.
//
// REF: https://github.com/golang/go/issues/14077
func newDefaultTransport() *http.Transport {
	return &http.Transport{
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
}

type httpFallback struct {
	super http.RoundTripper
	host  string
}

func (f *httpFallback) RoundTrip(r *http.Request) (*http.Response, error) {
	// only fall back if the same host had previously fell back
	if f.host != r.URL.Host {
		resp, err := f.super.RoundTrip(r)
		var tlsErr tls.RecordHeaderError
		if errors.As(err, &tlsErr) && string(tlsErr.RecordHeader[:]) == "HTTP/" {
			f.host = r.URL.Host
		} else {
			return resp, err
		}
	}

	plainHTTPUrl := *r.URL
	plainHTTPUrl.Scheme = "http"

	plainHTTPRequest := *r
	plainHTTPRequest.URL = &plainHTTPUrl

	return f.super.RoundTrip(&plainHTTPRequest)
}
