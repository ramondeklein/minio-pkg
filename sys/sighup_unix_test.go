//go:build linux || darwin || openbsd || netbsd || solaris || freebsd

// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package sys

import (
	"syscall"
	"testing"
	"time"
)

func TestRegisterSIGHUP(t *testing.T) {
	// Register multiple listeners
	ch1 := RegisterSIGHUP()
	ch2 := RegisterSIGHUP()

	if ch1 == nil || ch2 == nil {
		t.Fatal("RegisterSIGHUP returned nil channel")
	}

	// Channels should be different instances
	if ch1 == ch2 {
		t.Error("RegisterSIGHUP should return different channels for each call")
	}

	// Send SIGHUP to ourselves
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatalf("Failed to send SIGHUP: %v", err)
	}

	// Both channels should receive the signal
	timeout := time.After(time.Second)

	select {
	case <-ch1:
		// OK
	case <-timeout:
		t.Error("ch1 did not receive SIGHUP within timeout")
	}

	select {
	case <-ch2:
		// OK
	case <-timeout:
		t.Error("ch2 did not receive SIGHUP within timeout")
	}
}

func TestRegisterSIGHUPMultipleSignals(t *testing.T) {
	ch := RegisterSIGHUP()

	// Send multiple SIGHUPs
	for i := range 3 {
		if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatalf("Failed to send SIGHUP: %v", err)
		}

		timeout := time.After(time.Second)
		select {
		case <-ch:
			// OK
		case <-timeout:
			t.Errorf("Did not receive SIGHUP %d within timeout", i+1)
		}
	}
}
