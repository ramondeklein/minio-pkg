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
	"reflect"
	"syscall"
	"testing"
	"time"
)

func TestManager2_Close(t *testing.T) {
	loadCerts := func() ([]*Certificate2, error) {
		cert, err := NewCertificate2("public.crt")
		if err != nil {
			return nil, err
		}
		return []*Certificate2{cert}, nil
	}

	mgr, err := NewManager2(loadCerts)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	mgr.Close()

	time.Sleep(100 * time.Millisecond)

	certs := mgr.certs.Load()
	if len(*certs) != 0 {
		t.Error("Expected certificates to be cleared after close")
	}
}

func TestManager2_CloseMultipleTimes(t *testing.T) {
	loadCerts := func() ([]*Certificate2, error) {
		cert, err := NewCertificate2("public.crt")
		if err != nil {
			return nil, err
		}
		return []*Certificate2{cert}, nil
	}

	mgr, err := NewManager2(loadCerts)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	mgr.Close()
	mgr.Close()
	mgr.Close()
}

func TestManager2_ReloadOnSIGHUP(t *testing.T) {
	callCount := 0
	loadCerts := func() ([]*Certificate2, error) {
		certFile := "public.crt"
		if callCount%2 == 1 {
			certFile = "new-public.crt"
		}
		callCount++

		cert, err := NewCertificate2(certFile)
		if err != nil {
			return nil, err
		}
		return []*Certificate2{cert}, nil
	}

	mgr, err := NewManager2(loadCerts)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer mgr.Close()

	originalCerts := mgr.certs.Load()
	originalCert := (*originalCerts)[0].Load()

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("Failed to send SIGHUP: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	newCerts := mgr.certs.Load()
	newCert := (*newCerts)[0].Load()

	if reflect.DeepEqual(originalCert.Certificate, newCert.Certificate) {
		t.Error("Expected certificates to be reloaded after SIGHUP")
	}

	expectedCert, err := loadTLSCertificate("new-public.crt", "")
	if err != nil {
		t.Fatalf("Failed to load expected certificate: %v", err)
	}

	if !reflect.DeepEqual(newCert.Certificate, expectedCert.Certificate) {
		t.Error("Reloaded certificate doesn't match expected certificate")
	}
}
