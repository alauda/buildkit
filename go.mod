module github.com/moby/buildkit

go 1.25.0

require (
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.6.0
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v0.4.1
	github.com/Microsoft/go-winio v0.6.2
	github.com/Microsoft/hcsshim v0.11.7
	github.com/agext/levenshtein v1.2.3
	github.com/armon/circbuf v0.0.0-20190214190532-5111143e8da2
	github.com/aws/aws-sdk-go-v2 v1.41.7
	github.com/aws/aws-sdk-go-v2/config v1.32.17
	github.com/aws/aws-sdk-go-v2/credentials v1.19.16
	github.com/aws/aws-sdk-go-v2/feature/s3/manager v1.22.18
	github.com/aws/aws-sdk-go-v2/service/s3 v1.101.0
	github.com/containerd/console v1.0.4
	github.com/containerd/containerd v1.7.29
	github.com/containerd/containerd/api v1.8.0
	github.com/containerd/continuity v0.4.4
	github.com/containerd/fuse-overlayfs-snapshotter v1.0.8
	github.com/containerd/go-cni v1.1.9
	github.com/containerd/go-runc v1.1.0
	github.com/containerd/log v0.1.0
	github.com/containerd/nydus-snapshotter v0.13.7
	github.com/containerd/stargz-snapshotter v0.15.1
	github.com/containerd/stargz-snapshotter/estargz v0.15.1
	github.com/containerd/typeurl/v2 v2.2.0
	github.com/containernetworking/plugins v1.4.0
	github.com/coreos/go-systemd/v22 v22.5.0
	github.com/distribution/reference v0.6.0
	github.com/docker/cli v29.2.0+incompatible
	github.com/docker/distribution v2.8.2+incompatible
	github.com/docker/docker v28.0.4+incompatible
	github.com/docker/go-connections v0.5.0
	github.com/docker/go-units v0.5.0
	github.com/gofrs/flock v0.8.1
	github.com/gogo/googleapis v1.4.1
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.5.4
	github.com/google/go-cmp v0.7.0
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-immutable-radix v1.3.1
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/in-toto/in-toto-golang v0.11.0
	github.com/klauspost/compress v1.18.2
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/moby/docker-image-spec v1.3.1
	github.com/moby/locker v1.0.1
	github.com/moby/patternmatcher v0.6.0
	github.com/moby/sys/mountinfo v0.7.2
	github.com/moby/sys/signal v0.7.0
	github.com/moby/sys/user v0.4.0
	github.com/morikuni/aec v1.0.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.0
	github.com/opencontainers/runtime-spec v1.2.1
	github.com/opencontainers/selinux v1.13.0
	github.com/package-url/packageurl-go v0.1.1-0.20220428063043-89078438f170
	github.com/pelletier/go-toml v1.9.5
	github.com/pkg/errors v0.9.1
	github.com/pkg/profile v1.7.0
	github.com/prometheus/client_golang v1.20.5
	github.com/prometheus/procfs v0.15.1
	github.com/serialx/hashring v0.0.0-20200727003509-22c0c7ab6b1b
	github.com/sirupsen/logrus v1.9.3
	github.com/spdx/tools-golang v0.5.3
	github.com/stretchr/testify v1.11.1
	github.com/tonistiigi/fsutil v0.0.0-20240301111122-7525a1af2bb5
	github.com/tonistiigi/go-actions-cache v0.0.0-20240227172821-a0b64f338598
	github.com/tonistiigi/go-archvariant v1.0.0
	github.com/tonistiigi/units v0.0.0-20180711220420-6950e57a87ea
	github.com/tonistiigi/vt100 v0.0.0-20230623042737-f9a4f7ef6531
	github.com/urfave/cli v1.22.14
	github.com/vishvananda/netlink v1.2.1-beta.2
	go.etcd.io/bbolt v1.3.10
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.60.0
	go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace v0.60.0
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0
	go.opentelemetry.io/otel v1.43.0
	go.opentelemetry.io/otel/exporters/jaeger v1.17.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.43.0
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.43.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.43.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.43.0
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.43.0
	go.opentelemetry.io/otel/exporters/prometheus v0.55.0
	go.opentelemetry.io/otel/metric v1.43.0
	go.opentelemetry.io/otel/sdk v1.43.0
	go.opentelemetry.io/otel/sdk/metric v1.43.0
	go.opentelemetry.io/otel/trace v1.43.0
	go.opentelemetry.io/proto/otlp v1.10.0
	golang.org/x/crypto v0.49.0
	golang.org/x/mod v0.33.0
	golang.org/x/net v0.52.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.42.0
	golang.org/x/time v0.12.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260401024825-9d38bb4040a9
	google.golang.org/grpc v1.80.0
	google.golang.org/protobuf v1.36.11
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.67
)

require (
	cyphar.com/go-pathrs v0.2.1 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/AdamKorcz/go-118-fuzz-build v0.0.0-20230306123547-8075edf89bb0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.11.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.8.0 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/anchore/go-struct-converter v0.0.0-20221118182256-c68fdcfa2092 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.10 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.23 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.9 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.23 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.0.11 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.35.21 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.42.1 // indirect
	github.com/aws/smithy-go v1.25.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/cgroups v1.1.0 // indirect
	github.com/containerd/errdefs v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/containerd/ttrpc v1.2.7 // indirect
	github.com/containernetworking/cni v1.1.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/cyphar/filepath-securejoin v0.6.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/docker-credential-helpers v0.8.0 // indirect
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7 // indirect
	github.com/felixge/fgprof v0.9.3 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/pprof v0.0.0-20230323073829-e72429f035bd // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/hanwen/go-fuse/v2 v2.4.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/in-toto/attestation v1.1.2 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/moby/sys/mount v0.3.4 // indirect
	github.com/moby/sys/reexec v0.1.0 // indirect
	github.com/moby/sys/sequential v0.6.0 // indirect
	github.com/moby/sys/userns v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.61.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.10.0 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/vbatts/tar-split v0.11.5 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto v0.0.0-20231211222908-989df2bf70f3 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260401024825-9d38bb4040a9 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gotest.tools/v3 v3.5.2 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.67 // indirect
)
