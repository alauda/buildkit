// go:build (darwin && cgo) || linux
//go:build (darwin && cgo) || linux
// +build darwin,cgo linux

package resolver

import "testing"

func Test_isPlainHTTP(t *testing.T) {
	type args struct {
		host string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:    "http registry",
			args:    args{host: "registry.alauda.cn:60080"},
			want:    true,
			wantErr: false,
		},
		{
			name:    "https registry",
			args:    args{host: "docker.io"},
			want:    false,
			wantErr: true,
		},
		{
			name:    "not effective registry",
			args:    args{host: "github.com"},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isPlainHTTP(tt.args.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("isPlainHTTP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("isPlainHTTP() = %v, want %v", got, tt.want)
			}
		})
	}
}
