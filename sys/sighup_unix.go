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
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var (
	sighupMu        sync.Mutex
	sighupListeners []chan struct{}
)

// RegisterSIGHUP registers a new SIGHUP listener and returns a channel
// that receives an empty struct whenever a SIGHUP signal is received.
// The first call to RegisterSIGHUP will subscribe to the OS SIGHUP signal.
// Additional calls will register more listeners using the same OS subscription.
func RegisterSIGHUP() <-chan struct{} {
	sighupMu.Lock()
	defer sighupMu.Unlock()

	ch := make(chan struct{}, 1)
	sighupListeners = append(sighupListeners, ch)

	if len(sighupListeners) == 1 {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, syscall.SIGHUP)
		go func() {
			for range signalCh {
				sighupMu.Lock()
				for _, listener := range sighupListeners {
					select {
					case listener <- struct{}{}:
					default:
						// Channel is full; listener is not consuming notifications.
						// Skip to avoid blocking the signal handler.
					}
				}
				sighupMu.Unlock()
			}
		}()
	}

	return ch
}
