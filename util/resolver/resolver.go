package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/containerd/containerd/remotes/docker"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/transport"
	"github.com/docker/docker/dockerversion"
	"github.com/docker/docker/registry"
	"github.com/docker/go-connections/tlsconfig"
	"github.com/moby/buildkit/util"
	"github.com/moby/buildkit/util/resolver/config"
	"github.com/moby/buildkit/util/tracing"
	"github.com/pkg/errors"
)

func fillInsecureOpts(host string, c config.RegistryConfig, h docker.RegistryHost) ([]docker.RegistryHost, error) {
	var hosts []docker.RegistryHost

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

	if isHTTP {
		h2 := h
		h2.Scheme = "http"
		hosts = append(hosts, h2)
	}
	if c.Insecure != nil && *c.Insecure {
		h2 := h
		transport := newDefaultTransport()
		transport.TLSClientConfig = tc
		h2.Client = &http.Client{
			Transport: tracing.NewTransport(transport),
		}
		tc.InsecureSkipVerify = true
		hosts = append(hosts, h2)
	}

	if len(hosts) == 0 {
		transport := newDefaultTransport()
		transport.TLSClientConfig = tc

		h.Client = &http.Client{
			Transport: tracing.NewTransport(transport),
		}
		hosts = append(hosts, h)
	}

	return hosts, nil
}

func loadTLSConfig(c config.RegistryConfig) (*tls.Config, error) {
	for _, d := range c.TLSConfigDir {
		fs, err := ioutil.ReadDir(d)
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
		dt, err := ioutil.ReadFile(p)
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

			for _, mirror := range c.Mirrors {
				h := docker.RegistryHost{
					Scheme:       "https",
					Client:       newDefaultClient(),
					Host:         mirror,
					Path:         "/v2",
					Capabilities: docker.HostCapabilityPull | docker.HostCapabilityResolve,
				}

				hosts, err := fillInsecureOpts(mirror, m[mirror], h)
				if err != nil {
					return nil, err
				}

				out = append(out, hosts...)
			}

			if host == "docker.io" {
				host = "registry-1.docker.io"
			}

			h := docker.RegistryHost{
				Scheme:       "https",
				Client:       newDefaultClient(),
				Host:         host,
				Path:         "/v2",
				Capabilities: docker.HostCapabilityPush | docker.HostCapabilityPull | docker.HostCapabilityResolve,
			}

			hosts, err := fillInsecureOpts(host, c, h)
			if err != nil {
				return nil, err
			}

			out = append(out, hosts...)
			return out, nil
		},
		docker.ConfigureDefaultRegistries(
			docker.WithClient(util.DefaultInsecureClient()),
			docker.WithPlainHTTP(isPlainHTTP),
		),
	)
}

// MatchAllHosts is a host match function which is always true.
func isPlainHTTP(host string) (bool, error) {
	isHttp, err := docker.MatchLocalhost(host)
	if err != nil {
		return false, err
	}

	if isHttp {
		return isHttp, nil
	}

	tlsConfig := tlsconfig.ServerDefault()
	tlsConfig.InsecureSkipVerify = true

	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   true,
	}

	modifiers := registry.Headers(dockerversion.DockerUserAgent(context.Background()), nil)
	authTransport := transport.NewTransport(base, modifiers...)

	// By default, https attempts to authenticate the v2 interface.
	endpoint := &url.URL{
		Scheme: "https",
		Host:   host,
	}
	// If it is an https registry, PingV2Registry will return an error.
	foundV2, err := PingV2RegistryV2(endpoint, authTransport)
	// When an error is reported, it should be ignored.
	// because an error occurred, it was determined that the registry is not an http service.
	if err != nil {
		return true, nil
	}
	return !foundV2, nil
}

const (
	// DefaultRegistryVersionHeader is the name of the default HTTP header
	// that carries Registry version info
	DefaultRegistryVersionHeader = "Docker-Distribution-Api-Version"
)

func PingV2RegistryV2(endpoint *url.URL, transport http.RoundTripper) (bool, error) {
	var (
		foundV2   = false
		v2Version = auth.APIVersion{
			Type:    "registry",
			Version: "2.0",
		}
	)

	pingClient := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}
	endpointStr := strings.TrimRight(endpoint.String(), "/") + "/v2/"
	req, err := http.NewRequest(http.MethodGet, endpointStr, nil)
	if err != nil {
		return foundV2, err
	}
	resp, err := pingClient.Do(req)
	if err != nil {
		return foundV2, err
	}
	defer resp.Body.Close()

	versions := auth.APIVersions(resp, DefaultRegistryVersionHeader)
	for _, pingVersion := range versions {
		if pingVersion == v2Version {
			// The version header indicates we're definitely
			// talking to a v2 registry. So don't allow future
			// fallbacks to the v1 protocol.
			foundV2 = true
			break
		}
	}

	return foundV2, nil
}

func newDefaultClient() *http.Client {
	return &http.Client{
		Transport: tracing.NewTransport(newDefaultTransport()),
	}
}

func newDefaultInsecureClient() *http.Client {
	tc := &tls.Config{}
	transport := newDefaultTransport()
	transport.TLSClientConfig = tc
	tc.InsecureSkipVerify = true

	return &http.Client{
		Transport: tracing.NewTransport(transport),
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
