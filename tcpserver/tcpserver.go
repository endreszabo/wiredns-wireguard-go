//go:build !windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"fmt"
	"os"

	"net"
)

const (
	ExitSetupSuccess = 0
	ExitSetupFailed  = 1
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

const (
	CONN_HOST = "localhost"
	CONN_PORT = "3333"
	CONN_TYPE = "tcp"
)

func main() {
	// open UAPI file (or use supplied fd)
	l, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(ExitSetupFailed)
		return
	}
	fileUAPI, err := l.(*net.TCPListener).File()
	if err != nil {
		fmt.Println("Error getting fd:", err.Error())
		os.Exit(ExitSetupFailed)
		return
	}

	// daemonize the process

	env := os.Environ()
	env = append(env, fmt.Sprintf("%s=3", ENV_WG_TUN_FD))
	env = append(env, fmt.Sprintf("%s=1", ENV_WG_PROCESS_FOREGROUND))
	files := [3]*os.File{}
	files[0], _ = os.Open(os.DevNull)
	files[1] = os.Stdout
	files[2] = os.Stderr
	attr := &os.ProcAttr{
		Files: []*os.File{
			files[0], // stdin
			files[1], // stdout
			files[2], // stderr
			fileUAPI,
		},
		Dir: ".",
		Env: env,
	}

	path := "wireguard"

	fmt.Printf("attrs: %#v\n", attr)
	process, err := os.StartProcess(
		path,
		os.Args,
		attr,
	)
	if err != nil {
		fmt.Printf("Failed to daemonize: %v", err)
		os.Exit(ExitSetupFailed)
	}
	err = fileUAPI.Close()
	if err != nil {
		fmt.Printf("Failed to close UAPI fd: %v", err)
		os.Exit(2)
	}
	status, err := process.Wait()
	if err != nil {
		fmt.Printf("Failed to wait for child: %v", err)
		os.Exit(2)
	}
	fmt.Printf("Status: %#v", status)
	process.Release()
}
