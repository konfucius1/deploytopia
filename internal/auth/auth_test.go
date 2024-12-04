package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Table-driven test cases
	tests := []struct {
		name    string
		setup   func() http.Header
		want    string
		wantErr error
	}{
		{
			name: "valid API key",
			setup: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey test-api-key")
				return h
			},
			want:    "test-api-key",
			wantErr: nil,
		},
		{
			name: "missing Authorization header",
			setup: func() http.Header {
				return make(http.Header)
			},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing ApiKey prefix",
			setup: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "test-api-key")
				return h
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header - empty after prefix",
			setup: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey ")
				return h
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			headers := tt.setup()

			// Act
			got, err := GetAPIKey(headers)

			// Assert
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, wantErr = %v", tt.wantErr)
					return
				}
				if err.Error() != tt.wantErr.Error() {
					t.Errorf("GetAPIKey() error = %v, wantErr = %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
