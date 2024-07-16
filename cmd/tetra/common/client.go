// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func CliRunErr(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient), fnErr func(err error)) {
	c, err := NewClientWithDefaultContext()
	if err != nil {
		fnErr(err)
		return
	}
	defer c.Close()
	fn(c.Ctx, c.Client)
}

func CliRun(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient)) {
	CliRunErr(fn, func(_ error) {})
}

type ClientWithContext struct {
	Client tetragon.FineGuidanceSensorsClient
	Ctx    context.Context
	conn   *grpc.ClientConn
	cancel context.CancelFunc
}

// Close cleanup resources, it closes the connection and cancel the context
func (c ClientWithContext) Close() {
	c.conn.Close()
	c.cancel()
}

// NewClientWithDefaultContext return a client to a tetragon server accompanied
// with an initialized context that can be used for the RPC call, caller must
// call Close() on the client.
func NewClientWithDefaultContext() (*ClientWithContext, error) {
	c := &ClientWithContext{}

	var timeout context.Context
	timeout, c.cancel = context.WithTimeout(context.Background(), Timeout)
	// we don't need the cancelFunc here as calling cancel on timeout, the
	// parent, will cancel its children.
	c.Ctx, _ = signal.NotifyContext(timeout, syscall.SIGINT, syscall.SIGTERM)

	address, err := ResolveServerAddress()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	c.conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client with address %s: %w", address, err)
	}
	c.Client = tetragon.NewFineGuidanceSensorsClient(c.conn)

	return c, nil
}
