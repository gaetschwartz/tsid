// © 2024 Gaëtan Schwartz. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE.md file.

// Package tsid is a Caddy plugin that allows access only to
// requests coming from the Tailscale network and allows to identify
// users behind these requests by setting some Caddy placeholders.
package tsid

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

func init() {
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("tsid", parseCaddyfileHandler)
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tsid",
		New: func() caddy.Module { return &Middleware{} },
	}
}

// Middleware is a Caddy HTTP handler that allows requests only from
// the Tailscale network and sets placeholders based on the Tailscale
// node information.
type Middleware struct {
	RawAllowed   []string `json:"allowed,omitempty"`
	requirements *Requirements

	logger *zap.Logger
}

type Requirements struct {
	Ranges       []netip.Prefix
	Logins       []string
	Capabilities []string
}

const (
	TailscaleAdminCap = tailcfg.NodeCapability("https://tailscale.com/cap/is-admin")
)

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	if m.requirements.IsIpAllowed(ip) {
		return next.ServeHTTP(w, r)
	}

	if !tsaddr.IsTailscaleIP(ip) {
		return caddyhttp.Error(http.StatusForbidden, errors.New(fmt.Sprintf("Not a Tailscale IP: %s", ip.String())))
	}

	client := tailscale.LocalClient{}

	whois, err := client.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		if errors.Is(err, tailscale.ErrPeerNotFound) {
			return caddyhttp.Error(http.StatusForbidden, errors.New(fmt.Sprintf("Not found: %s", ip.String())))
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	m.logger.Debug("Tailscale user:", zap.Any("user", whois.Node.User), zap.Any("capabilities", whois.Node.CapMap))

	if !m.requirements.IsWhoIsLegal(whois) {
		return caddyhttp.Error(http.StatusForbidden, errors.New(fmt.Sprintf("User %s,%s not authorized", whois.UserProfile.DisplayName, whois.UserProfile.LoginName)))
	}

	caddyhttp.SetVar(r.Context(), "tailscale.name", whois.UserProfile.DisplayName)
	caddyhttp.SetVar(r.Context(), "tailscale.email", whois.UserProfile.LoginName)
	caddyhttp.SetVar(r.Context(), "tailscale.is-admin", whois.Node.HasCap(TailscaleAdminCap))

	return next.ServeHTTP(w, r)
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger() // g.logger is a *zap.Logger
	m.logger.Debug("", zap.Strings("allowed", m.RawAllowed))
	if allowed, err := parseAllowed(m.RawAllowed); err != nil {
		return err
	} else {
		m.requirements = allowed
		m.logger.Debug("Allowed: ", zap.Any("", allowed))
	}
	return nil
}

func (a Requirements) IsIpAllowed(ip netip.Addr) bool {
	for _, r := range a.Ranges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

func (a Requirements) IsLoginAllowed(s string) bool {
	return slices.Contains(a.Logins, s)
}
func (a Requirements) HasCapacities(m tailcfg.NodeCapMap) bool {
	for _, e := range a.Capabilities {
		if !m.Contains(tailcfg.NodeCapability(e)) {
			return false
		}
	}
	return true
}

func (a Requirements) IsWhoIsLegal(whoIs *apitype.WhoIsResponse) bool {
	return a.HasCapacities(whoIs.Node.CapMap) || a.IsLoginAllowed(whoIs.UserProfile.LoginName)
}

func parseAllowed(args []string) (*Requirements, error) {
	var ranges = make([]netip.Prefix, 0, len(args))
	var emails = make([]string, 0, len(args))
	var caps = make([]string, 0, len(args))
	for _, s := range args {
		before, after, found := strings.Cut(s, ":")
		if found {
			switch before {
			case RangePrefix:
				rg, err := parseAsRangeOrIp(after)
				if err != nil {
					return nil, err
				}
				ranges = append(ranges, rg)
			case LoginPrefix:
				emails = append(emails, after)
			case CapabilityPrefix:
				caps = append(caps, after)
			default:
				return nil, errors.New("Unknown prefix")
			}
		} else {
			rg, err := parseAsRangeOrIp(before)
			if err == nil {
				ranges = append(ranges, rg)
				continue
			}
			emails = append(emails, before)
		}
	}
	return &Requirements{
		Ranges:       ranges,
		Logins:       emails,
		Capabilities: caps,
	}, nil
}

func parseAsRangeOrIp(s2 string) (netip.Prefix, error) {
	if !strings.Contains(s2, "/") {
		s2 = s2 + "/32"
	}
	return netip.ParsePrefix(s2)
}

const (
	RangePrefix      = "ip"
	LoginPrefix      = "login"
	CapabilityPrefix = "cap"
)

// UnmarshalCaddyfile implements the caddyfile.Unmarshaler interface.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	// store the argument
	m.RawAllowed = d.RemainingArgs()
	return nil
}

// parseCaddyfileHandler unmarshals tokens from h into a new middleware handler value.
func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &Middleware{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func isWithinRange(ip netip.Addr, p netip.Prefix) bool {
	return p.Contains(ip)
}

// Interface guards.
var (
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)

const LenientEmailRegexString = "^[^@]+@[^@]+\\.[^@]+$"

var LenientEmailRegex *regexp.Regexp

func init() {
	emailRegex, err := regexp.Compile(LenientEmailRegexString)
	if err != nil {
		log.Fatalln("invalid email regex: ", err)
	} else {
		LenientEmailRegex = emailRegex
	}
}
