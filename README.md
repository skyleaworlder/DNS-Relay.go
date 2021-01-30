# :earth_asia: DNS-Relay.go

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
