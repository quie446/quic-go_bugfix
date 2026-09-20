package self_test

import (
	"context"
	"crypto/rand"
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

// natRouter simulates a NAT rebinding: once activated, packets from the client
// are sent from a new (NAT) address, and packets sent to the NAT address are
// forwarded to the client.
// It can also simulate the peer vanishing (e.g. after an abrupt close)
// by dropping all traffic.
type natRouter struct {
	simnet.PerfectRouter

	clientAddr *net.UDPAddr
	serverAddr *net.UDPAddr
	natAddr    *net.UDPAddr

	rebind atomic.Bool
	drop   atomic.Bool
}

func (r *natRouter) SendPacket(p simnet.Packet) error {
	if r.drop.Load() {
		return nil
	}
	if r.rebind.Load() {
		if p.From.String() == r.clientAddr.String() && p.To.String() == r.serverAddr.String() {
			p.From = r.natAddr
		} else if p.From.String() == r.serverAddr.String() && p.To.String() == r.natAddr.String() {
			p.To = r.clientAddr
		}
	}
	return r.PerfectRouter.SendPacket(p)
}

// requireUnblocksWithin asserts that the result of a blocking stream operation
// (delivered on errChan) arrives within d.
func requireUnblocksWithin(t *testing.T, d time.Duration, errChan <-chan error) error {
	t.Helper()
	select {
	case err := <-errChan:
		return err
	case <-time.After(d):
		t.Fatal("stream operation did not unblock within the deadline")
		return nil
	}
}

// A stateless reset must unblock a pending Read with a StatelessResetError,
// even if the connection's idle timeout is long.
func TestStatelessResetUnblocksPendingRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var drop atomic.Bool
		clientPacketConn, serverPacketConn, closeFn := newSimnetLinkWithRouter(t,
			time.Millisecond,
			&droppingRouter{Drop: func(p simnet.Packet) bool { return drop.Load() }},
		)
		defer closeFn(t)

		var statelessResetKey quic.StatelessResetKey
		rand.Read(statelessResetKey[:])

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
			_, err = str.Write([]byte("foobar"))
			if err != nil {
				serverErr <- err
				return
			}
			close(serverErr)
		}()

		// use a long idle timeout: the read must be unblocked by the stateless
		// reset, not by the idle timeout
		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			serverPacketConn.LocalAddr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{MaxIdleTimeout: time.Hour}),
		)
		require.NoError(t, err)

		str, err := conn.AcceptStream(context.Background())
		require.NoError(t, err)
		_, err = str.Read(make([]byte, 6))
		require.NoError(t, err)

		readErr := make(chan error, 1)
		go func() {
			_, err := str.Read(make([]byte, 1))
			readErr <- err
		}()

		// kill the server: make sure the CONNECTION_CLOSE is dropped
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

		// trigger a packet to be sent, so that we receive the stateless reset
		_, werr := str.Write([]byte("Lorem ipsum dolor sit amet."))
		if werr == nil {
			err = requireUnblocksWithin(t, 10*time.Second, readErr)
		} else {
			err = werr
		}
		require.Error(t, err)
		require.IsType(t, &quic.StatelessResetError{}, err)
	})
}

// When the peer vanishes (half-open connection), a pending Read must return
// an IdleTimeoutError once the idle timeout expires. It must not hang forever.
func TestIdleTimeoutUnblocksPendingRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idleTimeout = 5 * time.Second

		var drop atomic.Bool
		clientPacketConn, serverPacketConn, closeFn := newSimnetLinkWithRouter(t,
			time.Millisecond,
			&droppingRouter{Drop: func(p simnet.Packet) bool { return drop.Load() }},
		)
		defer closeFn(t)

		server, err := quic.Listen(
			serverPacketConn,
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		require.NoError(t, err)
		defer server.Close()

		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			server.Addr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, MaxIdleTimeout: idleTimeout}),
		)
		require.NoError(t, err)

		serverConn, err := server.Accept(context.Background())
		require.NoError(t, err)

		str, err := conn.OpenStream()
		require.NoError(t, err)
		_, err = str.Write([]byte("ping"))
		require.NoError(t, err)
		serverStr, err := serverConn.AcceptStream(context.Background())
		require.NoError(t, err)
		_, err = serverStr.Read(make([]byte, 4))
		require.NoError(t, err)
		_, err = serverStr.Write([]byte("pong"))
		require.NoError(t, err)
		_, err = str.Read(make([]byte, 4))
		require.NoError(t, err)

		clientReadErr := make(chan error, 1)
		go func() {
			_, err := str.Read(make([]byte, 1))
			clientReadErr <- err
		}()
		serverReadErr := make(chan error, 1)
		go func() {
			_, err := serverStr.Read(make([]byte, 1))
			serverReadErr <- err
		}()

		// the peer vanishes without a trace
		drop.Store(true)

		requireIdleTimeoutError(t, requireUnblocksWithin(t, 2*idleTimeout, clientReadErr))
		requireIdleTimeoutError(t, requireUnblocksWithin(t, 2*idleTimeout, serverReadErr))

		select {
		case <-conn.Context().Done():
		case <-time.After(2 * idleTimeout):
			t.Fatal("client connection did not time out")
		}
		select {
		case <-serverConn.Context().Done():
		case <-time.After(2 * idleTimeout):
			t.Fatal("server connection did not time out")
		}
	})
}

// If the peer vanishes right around the path validation window (PATH_CHALLENGE
// in flight after a NAT rebinding), the connection must still time out and
// pending Reads must return an IdleTimeoutError.
func TestAbruptCloseDuringPathValidation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idleTimeout = 5 * time.Second

		clientAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		router := &natRouter{
			clientAddr: clientAddr,
			serverAddr: serverAddr,
			natAddr:    &net.UDPAddr{IP: net.ParseIP("1.0.0.3"), Port: 9003},
		}
		n := &simnet.Simnet{Router: router}
		settings := simnet.NodeBiDiLinkSettings{Latency: time.Millisecond / 2}
		clientPacketConn := n.NewEndpoint(clientAddr, settings)
		serverPacketConn := n.NewEndpoint(serverAddr, settings)
		require.NoError(t, n.Start())
		defer func() {
			require.NoError(t, clientPacketConn.Close())
			require.NoError(t, serverPacketConn.Close())
			require.NoError(t, n.Close())
		}()

		server, err := quic.Listen(
			serverPacketConn,
			getTLSConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true}),
		)
		require.NoError(t, err)
		defer server.Close()

		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			server.Addr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{DisablePathMTUDiscovery: true, MaxIdleTimeout: idleTimeout}),
		)
		require.NoError(t, err)

		serverConn, err := server.Accept(context.Background())
		require.NoError(t, err)

		serverStr, err := serverConn.OpenStream()
		require.NoError(t, err)
		_, err = serverStr.Write([]byte("foobar"))
		require.NoError(t, err)
		str, err := conn.AcceptStream(context.Background())
		require.NoError(t, err)
		_, err = str.Read(make([]byte, 6))
		require.NoError(t, err)

		// NAT rebinding: the client's packets now arrive from a new address.
		// The server responds with a PATH_CHALLENGE.
		router.rebind.Store(true)
		clientStr, err := conn.OpenStream()
		require.NoError(t, err)
		_, err = clientStr.Write([]byte("ping"))
		require.NoError(t, err)
		serverClientStr, err := serverConn.AcceptStream(context.Background())
		require.NoError(t, err)
		// drain the data the client sent
		_, err = serverClientStr.Read(make([]byte, 4))
		require.NoError(t, err)

		// The peer vanishes in the middle of the path validation window.
		router.drop.Store(true)

		serverReadErr := make(chan error, 1)
		go func() {
			_, err := serverClientStr.Read(make([]byte, 1))
			serverReadErr <- err
		}()
		clientReadErr := make(chan error, 1)
		go func() {
			_, err := str.Read(make([]byte, 1))
			clientReadErr <- err
		}()

		requireIdleTimeoutError(t, requireUnblocksWithin(t, 3*idleTimeout, serverReadErr))
		requireIdleTimeoutError(t, requireUnblocksWithin(t, 3*idleTimeout, clientReadErr))

		select {
		case <-serverConn.Context().Done():
		case <-time.After(3 * idleTimeout):
			t.Fatal("server connection did not time out")
		}
		select {
		case <-conn.Context().Done():
		case <-time.After(3 * idleTimeout):
			t.Fatal("client connection did not time out")
		}
	})
}

// A stateless reset received while the connection is probing a new path
// (PATH_CHALLENGE in flight) must still tear down the connection and unblock
// pending Reads with a StatelessResetError.
func TestStatelessResetDuringPathValidation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.1"), Port: 9001}
		serverAddr := &net.UDPAddr{IP: net.ParseIP("1.0.0.2"), Port: 9002}
		router := &natRouter{
			clientAddr: clientAddr,
			serverAddr: serverAddr,
			natAddr:    &net.UDPAddr{IP: net.ParseIP("1.0.0.3"), Port: 9003},
		}
		n := &simnet.Simnet{Router: router}
		settings := simnet.NodeBiDiLinkSettings{Latency: time.Millisecond / 2}
		clientPacketConn := n.NewEndpoint(clientAddr, settings)
		serverPacketConn := n.NewEndpoint(serverAddr, settings)
		require.NoError(t, n.Start())
		defer func() {
			require.NoError(t, clientPacketConn.Close())
			require.NoError(t, serverPacketConn.Close())
			require.NoError(t, n.Close())
		}()

		var statelessResetKey quic.StatelessResetKey
		rand.Read(statelessResetKey[:])

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
			_, err = str.Write([]byte("foobar"))
			if err != nil {
				serverErr <- err
				return
			}
			close(serverErr)
		}()

		// long idle timeout: the read must be unblocked by the stateless reset
		conn, err := quic.Dial(
			context.Background(),
			clientPacketConn,
			ln.Addr(),
			getTLSClientConfig(),
			getQuicConfig(&quic.Config{MaxIdleTimeout: time.Hour}),
		)
		require.NoError(t, err)

		str, err := conn.AcceptStream(context.Background())
		require.NoError(t, err)
		_, err = str.Read(make([]byte, 6))
		require.NoError(t, err)

		// NAT rebinding: the server now sees the client on a new path and
		// starts path validation.
		router.rebind.Store(true)

		readErr := make(chan error, 1)
		go func() {
			_, err := str.Read(make([]byte, 1))
			readErr <- err
		}()

		// The server dies abruptly while the PATH_CHALLENGE is in flight:
		// its CONNECTION_CLOSE is dropped, and a new Transport (sharing the
		// stateless reset key) comes up on the same address.
		router.drop.Store(true)
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
		router.drop.Store(false)

		// trigger a packet so that we receive the stateless reset
		_, werr := str.Write([]byte("Lorem ipsum dolor sit amet."))
		if werr == nil {
			err = requireUnblocksWithin(t, 10*time.Second, readErr)
		} else {
			err = werr
		}
		require.Error(t, err)
		var statelessResetErr *quic.StatelessResetError
		require.True(t, errors.As(err, &statelessResetErr), "expected StatelessResetError, got: %v", err)
	})
}

// If the peer vanishes while a path probe (PATH_CHALLENGE) is in flight,
// the connection eventually times out. Path.Probe must return the connection's
// close error instead of blocking forever.
func TestPathProbeReturnsWhenConnectionDies(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idleTimeout = time.Second

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

		ln, err := quic.Listen(serverConn, getTLSConfig(), getQuicConfig(nil))
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
			getQuicConfig(&quic.Config{MaxIdleTimeout: idleTimeout}),
		)
		require.NoError(t, err)

		tr2 := &quic.Transport{Conn: clientConn2}
		defer tr2.Close()
		path, err := conn.AddPath(tr2)
		require.NoError(t, err)

		// The peer vanishes right when we start probing the new path.
		drop.Store(true)

		probeErr := make(chan error, 1)
		go func() { probeErr <- path.Probe(context.Background()) }()

		select {
		case err := <-probeErr:
			requireIdleTimeoutError(t, err)
		case <-time.After(10 * idleTimeout):
			t.Fatal("Path.Probe did not return after the connection timed out")
		}

		// The connection itself must be dead by now.
		require.Error(t, conn.Context().Err())
		require.NoError(t, <-serverErr)

		// Adding or switching paths on a closed connection must fail immediately.
		_, err = conn.AddPath(&quic.Transport{Conn: clientConn1})
		require.Error(t, err)
		require.ErrorIs(t, path.Switch(), quic.ErrPathClosed)
	})
}
