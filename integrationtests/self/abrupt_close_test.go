package self_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/testutils/simnet"

	"github.com/stretchr/testify/require"
)

// TestAbruptCloseUnblocksRead simulates a peer that vanishes without sending
// CONNECTION_CLOSE (e.g. a crashed process): all packets are dropped from one
// moment to the next. A blocked Read must return an IdleTimeoutError within a
// bounded amount of time instead of hanging forever.
func TestAbruptCloseUnblocksRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var drop atomic.Bool
		clientPacketConn, serverPacketConn, closeFn := newSimnetLinkWithRouter(t,
			time.Millisecond,
			&droppingRouter{Drop: func(p simnet.Packet) bool { return drop.Load() }},
		)
		defer closeFn(t)

		tr := &quic.Transport{Conn: serverPacketConn}
		defer tr.Close()
		ln, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)

		serverErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				serverErr <- err
				return
			}
			str, err := conn.OpenStream()
			if err != nil {
				serverErr <- err
				return
			}
			if _, err := str.Write([]byte("foobar")); err != nil {
				serverErr <- err
				return
			}
			// keep the connection alive until it is closed by the test
			<-conn.Context().Done()
			close(serverErr)
		}()

		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{MaxIdleTimeout: time.Second}),
		)
		require.NoError(t, err)

		str, err := conn.AcceptStream(context.Background())
		require.NoError(t, err)
		data := make([]byte, 6)
		_, err = str.Read(data)
		require.NoError(t, err)
		require.Equal(t, []byte("foobar"), data)

		// The peer crashes: it doesn't send a CONNECTION_CLOSE, it just stops
		// sending and receiving packets.
		drop.Store(true)
		require.NoError(t, ln.Close())
		require.NoError(t, tr.Close())
		require.NoError(t, <-serverErr)

		start := time.Now()
		_, err = str.Read(make([]byte, 1))
		require.Error(t, err)
		var idleTimeoutErr *quic.IdleTimeoutError
		require.True(t, errors.As(err, &idleTimeoutErr), "expected IdleTimeoutError, got: %v", err)
		// The idle timeout is 1s. Allow a generous margin for PTO probes.
		require.Less(t, time.Since(start), 10*time.Second)
	})
}

// TestStatelessResetUnblocksPendingRead checks that a Read that is blocked when
// a stateless reset is received returns a StatelessResetError.
func TestStatelessResetUnblocksPendingRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var drop atomic.Bool
		clientPacketConn, serverPacketConn, closeFn := newSimnetLinkWithRouter(t,
			time.Millisecond,
			&droppingRouter{Drop: func(p simnet.Packet) bool { return drop.Load() }},
		)
		defer closeFn(t)

		var statelessResetKey quic.StatelessResetKey
		tr := &quic.Transport{
			Conn:              serverPacketConn,
			StatelessResetKey: &statelessResetKey,
		}
		defer tr.Close()
		ln, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)

		serverErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				serverErr <- err
				return
			}
			str, err := conn.OpenStream()
			if err != nil {
				serverErr <- err
				return
			}
			if _, err := str.Write([]byte("foobar")); err != nil {
				serverErr <- err
				return
			}
			<-conn.Context().Done()
			close(serverErr)
		}()

		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{MaxIdleTimeout: 30 * time.Second}),
		)
		require.NoError(t, err)

		str, err := conn.AcceptStream(context.Background())
		require.NoError(t, err)
		data := make([]byte, 6)
		_, err = str.Read(data)
		require.NoError(t, err)
		require.Equal(t, []byte("foobar"), data)

		readErr := make(chan error, 1)
		go func() {
			_, err := str.Read(make([]byte, 1))
			readErr <- err
		}()

		// The server restarts and loses all connection state. The
		// CONNECTION_CLOSE sent by the old transport is dropped.
		drop.Store(true)
		require.NoError(t, ln.Close())
		require.NoError(t, tr.Close())
		require.NoError(t, <-serverErr)
		time.Sleep(100 * time.Millisecond)

		tr2 := &quic.Transport{
			Conn:              serverPacketConn,
			StatelessResetKey: &statelessResetKey,
		}
		defer tr2.Close()
		ln2, err := tr2.Listen(getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln2.Close()
		drop.Store(false)

		// Trigger the client to send a packet, causing the server to respond
		// with a stateless reset.
		_, werr := str.Write([]byte("Lorem ipsum dolor sit amet."))
		if werr != nil {
			var statelessResetErr *quic.StatelessResetError
			require.True(t, errors.As(werr, &statelessResetErr), "expected StatelessResetError, got: %v", werr)
		}

		select {
		case err := <-readErr:
			var statelessResetErr *quic.StatelessResetError
			require.True(t, errors.As(err, &statelessResetErr), "expected StatelessResetError, got: %v", err)
		case <-time.After(10 * time.Second):
			t.Fatal("Read did not return after the stateless reset was received")
		}
	})
}

// TestPathProbeReturnsWhenConnectionDies checks that Path.Probe doesn't hang
// forever when the peer vanishes in the middle of path validation: once the
// connection times out, Probe must return an error.
func TestPathProbeReturnsWhenConnectionDies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var drop atomic.Bool
		n := &simnet.Simnet{Router: &droppingRouter{Drop: func(p simnet.Packet) bool { return drop.Load() }}}
		settings := simnet.NodeBiDiLinkSettings{Latency: time.Millisecond}
		clientConn1 := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}, settings)
		clientConn2 := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9002}, settings)
		serverConn := n.NewEndpoint(&net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 1234}, settings)
		require.NoError(t, n.Start())
		defer func() {
			require.NoError(t, clientConn1.Close())
			require.NoError(t, clientConn2.Close())
			require.NoError(t, serverConn.Close())
			require.NoError(t, n.Close())
		}()

		tr := &quic.Transport{Conn: serverConn}
		defer tr.Close()
		ln, err := tr.Listen(getTLSConfig(), getQuicConfig(nil))
		require.NoError(t, err)
		defer ln.Close()

		serverErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				serverErr <- err
				return
			}
			<-conn.Context().Done()
			close(serverErr)
		}()

		tr1 := &quic.Transport{Conn: clientConn1}
		defer tr1.Close()
		conn, err := tr1.Dial(
			context.Background(),
			serverConn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{MaxIdleTimeout: time.Second}),
		)
		require.NoError(t, err)

		tr2 := &quic.Transport{Conn: clientConn2}
		defer tr2.Close()
		path, err := conn.AddPath(tr2)
		require.NoError(t, err)

		// The peer vanishes right when we start probing the new path.
		drop.Store(true)

		probeCtx, cancelProbe := context.WithCancel(context.Background())
		defer cancelProbe()
		probeErr := make(chan error, 1)
		go func() { probeErr <- path.Probe(probeCtx) }()

		select {
		case err := <-probeErr:
			require.Error(t, err)
			var idleTimeoutErr *quic.IdleTimeoutError
			require.True(t, errors.As(err, &idleTimeoutErr), "expected IdleTimeoutError, got: %v", err)
		case <-time.After(30 * time.Second):
			t.Fatal("Path.Probe did not return after the connection timed out")
		}

		// The connection itself must be dead by now.
		require.Error(t, conn.Context().Err())
		require.NoError(t, <-serverErr)
	})
}
