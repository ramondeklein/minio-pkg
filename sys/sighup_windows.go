//go:build windows

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

// RegisterSIGHUP registers a new SIGHUP listener and returns a channel
// that receives an empty struct whenever a SIGHUP signal is received.
// On Windows, SIGHUP does not exist, so this returns a channel that
// will never receive any events.
func RegisterSIGHUP() <-chan struct{} {
	// SIGHUP does not exist on Windows.
	// Return a channel that will never receive events.
	return make(chan struct{})
}
