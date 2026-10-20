package self_test

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestBBRTransfer(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		clientRate, serverRate uint64
	}{{"client", 1_000_000, 0}, {"server", 0, 1_000_000}, {"both", 1_000_000, 1_000_000}} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := quic.ListenAddr("127.0.0.1:0", getTLSConfig(), getQuicConfig(&quic.Config{MaxPacingRate: tc.serverRate}))
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			client, err := quic.DialAddr(ctx, listener.Addr().String(), getTLSClientConfig(), getQuicConfig(&quic.Config{MaxPacingRate: tc.clientRate}))
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseWithError(0, "")
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer server.CloseWithError(0, "")
			serverDone := make(chan error, 1)
			go func() {
				stream, err := server.AcceptStream(ctx)
				if err != nil {
					serverDone <- err
					return
				}
				data, err := io.ReadAll(stream)
				if err == nil {
					_, err = io.Copy(stream, bytes.NewReader(data))
				}
				if err == nil {
					err = stream.Close()
				}
				serverDone <- err
			}()
			stream, err := client.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
			data := bytes.Repeat([]byte("BBR"), 24*1024)
			if _, err := io.Copy(stream, bytes.NewReader(data)); err != nil {
				t.Fatal(err)
			}
			if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			received, err := io.ReadAll(stream)
			if err != nil || !bytes.Equal(data, received) {
				t.Fatalf("BBR transfer failed: %v", err)
			}
			if err := <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
