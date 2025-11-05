// Copyright (c) 2015-2022 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package certs

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func init() {
	// Reload symlinks every second for faster tests
	symlinkReloadInterval = time.Second
}

func TestNewCertificate2(t *testing.T) {
	cert, err := NewCertificate2("public.crt")
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	if cert.Load() == nil {
		t.Error("Expected loaded certificate, got nil")
	}

	expectedCert, err := loadTLSCertificate("public.crt", "")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	loadedCert := cert.Load()
	if !reflect.DeepEqual(loadedCert.Certificate, expectedCert.Certificate) {
		t.Error("Loaded certificate doesn't match expected certificate")
	}
}

func TestNewCertificate2WithKey(t *testing.T) {
	cert, err := NewCertificate2WithKey("public.crt", "private.key")
	if err != nil {
		t.Fatalf("Failed to create certificate with key: %v", err)
	}
	defer cert.Close()

	if cert.Load() == nil {
		t.Error("Expected loaded certificate, got nil")
	}

	expectedCert, err := tls.LoadX509KeyPair("public.crt", "private.key")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	loadedCert := cert.Load()
	if !reflect.DeepEqual(loadedCert.Certificate, expectedCert.Certificate) {
		t.Error("Loaded certificate doesn't match expected certificate")
	}
}

func TestNewCertificate2_InvalidFile(t *testing.T) {
	_, err := NewCertificate2("nonexistent.crt")
	if err == nil {
		t.Error("Expected error for nonexistent file, got nil")
	}
}

func TestNewCertificate2WithKey_InvalidCertFile(t *testing.T) {
	_, err := NewCertificate2WithKey("nonexistent.crt", "private.key")
	if err == nil {
		t.Error("Expected error for nonexistent cert file, got nil")
	}
}

func TestNewCertificate2WithKey_InvalidKeyFile(t *testing.T) {
	_, err := NewCertificate2WithKey("public.crt", "nonexistent.key")
	if err == nil {
		t.Error("Expected error for nonexistent key file, got nil")
	}
}

func TestNewCertificate2WithKey_MismatchedPair(t *testing.T) {
	_, err := NewCertificate2WithKey("new-public.crt", "private.key")
	if err == nil {
		t.Error("Expected error for mismatched cert/key pair, got nil")
	}
}

func TestCertificate2Close(t *testing.T) {
	cert, err := NewCertificate2("public.crt")
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert.Close()
}

func TestCertificate2_AutoReloadSingleFile(t *testing.T) {
	testCertificate2AutoReloadSingleFile(t, false)
}

func TestCertificate2_AutoReloadSingleFileSymlink(t *testing.T) {
	testCertificate2AutoReloadSingleFile(t, true)
}

func testCertificate2AutoReloadSingleFile(t *testing.T, symlink bool) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")

	copyFile(t, "public.crt", tmpCert, symlink)

	cert, err := NewCertificate2(tmpCert)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	originalCert := cert.Load()

	overwriteFile(t, "new-public.crt", tmpCert, symlink)

	waitForCert(symlink)

	newCert := cert.Load()
	if reflect.DeepEqual(originalCert.Certificate, newCert.Certificate) {
		t.Error("Certificate was not reloaded after file change")
	}

	expectedCert, err := loadTLSCertificate("new-public.crt", "")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	if !reflect.DeepEqual(newCert.Certificate, expectedCert.Certificate) {
		t.Error("Reloaded certificate doesn't match expected certificate")
	}
}

func TestCertificate2_AutoReloadWithKey(t *testing.T) {
	testCertificate2AutoReloadWithKey(t, false)
}

func TestCertificate2_AutoReloadWithKeySymlink(t *testing.T) {
	testCertificate2AutoReloadWithKey(t, true)
}

func testCertificate2AutoReloadWithKey(t *testing.T, symlink bool) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")
	tmpKey := filepath.Join(tmpDir, "test.key")

	copyFile(t, "public.crt", tmpCert, symlink)
	copyFile(t, "private.key", tmpKey, symlink)

	cert, err := NewCertificate2WithKey(tmpCert, tmpKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	originalCert := cert.Load()

	overwriteFile(t, "new-public.crt", tmpCert, symlink)
	overwriteFile(t, "new-private.key", tmpKey, symlink)
	waitForCert(symlink)

	newCert := cert.Load()
	if reflect.DeepEqual(originalCert.Certificate, newCert.Certificate) {
		t.Error("Certificate was not reloaded after file change")
	}

	expectedCert, err := tls.LoadX509KeyPair("new-public.crt", "new-private.key")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	if !reflect.DeepEqual(newCert.Certificate, expectedCert.Certificate) {
		t.Error("Reloaded certificate doesn't match expected certificate")
	}
}

func TestCertificate2_AutoReloadCertFileOnly(t *testing.T) {
	testCertificate2AutoReloadCertFileOnly(t, false)
}

func TestCertificate2_AutoReloadCertFileOnlySymlink(t *testing.T) {
	testCertificate2AutoReloadCertFileOnly(t, true)
}

func testCertificate2AutoReloadCertFileOnly(t *testing.T, symlink bool) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")
	tmpKey := filepath.Join(tmpDir, "test.key")

	copyFile(t, "public.crt", tmpCert, symlink)
	copyFile(t, "private.key", tmpKey, symlink)

	cert, err := NewCertificate2WithKey(tmpCert, tmpKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	overwriteFile(t, "new-public.crt", tmpCert, symlink)
	overwriteFile(t, "new-private.key", tmpKey, symlink)
	waitForCert(symlink)

	newCert := cert.Load()

	expectedCert, err := tls.LoadX509KeyPair("new-public.crt", "new-private.key")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	if !reflect.DeepEqual(newCert.Certificate, expectedCert.Certificate) {
		t.Error("Certificate was not reloaded after cert file change")
	}
}

func TestCertificate2_InvalidReloadIgnored(t *testing.T) {
	testCertificate2InvalidReloadIgnored(t, false)
}

func TestCertificate2_InvalidReloadIgnoredSymlink(t *testing.T) {
	testCertificate2InvalidReloadIgnored(t, true)
}

func testCertificate2InvalidReloadIgnored(t *testing.T, symlink bool) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "test.crt")

	copyFile(t, "public.crt", tmpCert, symlink)

	cert, err := NewCertificate2(tmpCert)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}
	defer cert.Close()

	validCert := cert.Load()

	if symlink {
		tmpCert = tmpCert + ".tmp"
	}

	if err := os.WriteFile(tmpCert, []byte("invalid certificate data"), 0o600); err != nil {
		t.Fatalf("Failed to write invalid cert: %v", err)
	}

	waitForCert(symlink)

	currentCert := cert.Load()
	if !reflect.DeepEqual(validCert.Certificate, currentCert.Certificate) {
		t.Error("Certificate should remain unchanged after invalid reload attempt")
	}
}

func TestLoadTLSCertificate_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "empty.crt")

	if err := os.WriteFile(tmpCert, []byte(""), 0o600); err != nil {
		t.Fatalf("Failed to create empty cert file: %v", err)
	}

	_, err := loadTLSCertificate(tmpCert, "")
	if err == nil {
		t.Error("Expected error for empty certificate file, got nil")
	}
}

func TestLoadTLSCertificate_NoCertificateBlock(t *testing.T) {
	tmpDir := t.TempDir()
	tmpCert := filepath.Join(tmpDir, "nocert.crt")

	pemData := `-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALRiMLAA...
-----END RSA PRIVATE KEY-----`

	if err := os.WriteFile(tmpCert, []byte(pemData), 0o600); err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}

	_, err := loadTLSCertificate(tmpCert, "")
	if err == nil {
		t.Error("Expected error for file with no CERTIFICATE block, got nil")
	}
}

func copyFile(t *testing.T, src, dst string, symlink bool) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("Failed to read source file %s: %v", src, err)
	}
	tmp := dst
	if symlink {
		tmp = dst + ".tmp"
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("Failed to write destination file %s: %v", dst, err)
	}
	if symlink {
		if err := os.Symlink(tmp, dst); err != nil {
			t.Fatalf("Failed to create symlink: %v", err)
		}
	}
}

func overwriteFile(t *testing.T, src, dst string, symlink bool) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("Failed to read source file %s: %v", src, err)
	}
	if symlink {
		dst = dst + ".tmp"
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("Failed to write destination file %s: %v", dst, err)
	}
}

func waitForCert(symlink bool) {
	if symlink {
		time.Sleep(symlinkReloadInterval + time.Second)
	} else {
		time.Sleep(500 * time.Millisecond)
	}
}
