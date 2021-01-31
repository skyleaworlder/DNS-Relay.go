# :earth_asia: DNS-Relay.go

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fskyleaworlder%2FDNS-Relay.go.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fskyleaworlder%2FDNS-Relay.go?ref=badge_shield)  [![Build Status](https://travis-ci.org/skyleaworlder/DNS-Relay.go.svg?branch=main)](https://travis-ci.org/skyleaworlder/DNS-Relay.go)

(semi-finished) RFC-1035 / RFC-2535 Learning "Note", a Simple Toy about DNS in Go.

Change DNS address on PC:

```bash
// Administrator Mode on Win10-Terminal
C:\User\UserName> netsh
netsh> interface
netsh interface> ipv4
netsh interface ipv4> set dnsserver "WLAN" static 127.0.0.1
```

Execute `main.go`:

```bash
go run main.go
```

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fskyleaworlder%2FDNS-Relay.go.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fskyleaworlder%2FDNS-Relay.go?ref=badge_large)
