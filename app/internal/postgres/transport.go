package postgres

import (
	"context"
	"errors"
	"net"
)

var ErrPrivateDatabaseEndpoint = errors.New("private database mode requires a private or loopback network address")

// Validate the address actually dialed, including every reconnect and fallback.
// Dial a resolved IP so DNS cannot change the destination after validation.
func dialPrivatePostgres(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrPrivateDatabaseEndpoint
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrPrivateDatabaseEndpoint
	}
	addresses := []net.IPAddr{}
	if ip := net.ParseIP(host); ip != nil {
		addresses = append(addresses, net.IPAddr{IP: ip})
	} else {
		addresses, err = net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
	}
	if len(addresses) == 0 {
		return nil, ErrPrivateDatabaseEndpoint
	}
	for _, address := range addresses {
		if !address.IP.IsPrivate() && !address.IP.IsLoopback() {
			return nil, ErrPrivateDatabaseEndpoint
		}
	}
	dialer := net.Dialer{}
	for _, address := range addresses {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		err = dialErr
	}
	return nil, err
}
