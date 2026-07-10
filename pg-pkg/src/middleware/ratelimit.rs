//! Rate-limiting key extraction.
//!
//! `actix-governor`'s built-in [`PeerIpKeyExtractor`] keys on the TCP peer
//! address. Behind a reverse proxy the peer is always the proxy, so every
//! client collapses into a single bucket and the rate limiter throttles all
//! traffic as if it came from one user.
//!
//! [`ClientIpKeyExtractor`] fixes this for proxied deployments: when
//! `trust_forwarded_for` is set it keys on the real client IP taken from the
//! *rightmost* `X-Forwarded-For` entry — the hop appended by the trusted
//! proxy — falling back to the peer address when the header is absent or
//! unparseable.
//!
//! [`PeerIpKeyExtractor`]: actix_governor::PeerIpKeyExtractor

use std::net::IpAddr;

use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
use actix_web::dev::ServiceRequest;

/// `X-Forwarded-For` — looked up case-insensitively by `HeaderMap::get`.
const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// A [`KeyExtractor`] that keys rate limiting on the client IP.
///
/// When [`trust_forwarded_for`](Self::trust_forwarded_for) is `false` (the
/// default) it behaves like `PeerIpKeyExtractor` and keys on the TCP peer.
/// When `true` it keys on the **rightmost** `X-Forwarded-For` entry.
///
/// # Why the rightmost entry
///
/// `X-Forwarded-For` is a comma-separated list that each proxy *appends* to.
/// A reverse proxy such as ingress-nginx appends the address it received the
/// connection from as the **last** entry, so the rightmost entry is the only
/// one we can trust — everything to its left was supplied by the client (or an
/// upstream we do not control) and is therefore spoofable. We deliberately do
/// **not** walk further left when the rightmost entry fails to parse; we fall
/// back to the peer address instead. This mirrors the `XFF_DEPTH=1` handling
/// the rest of the platform uses behind the same ingress.
///
/// Only enable `trust_forwarded_for` when the PKG actually runs behind a
/// trusted proxy — trusting the header when the PKG is directly reachable would
/// let any client forge its rate-limit key.
#[derive(Debug, Clone, Copy)]
pub struct ClientIpKeyExtractor {
    pub trust_forwarded_for: bool,
}

impl ClientIpKeyExtractor {
    fn peer_ip(req: &ServiceRequest) -> Option<IpAddr> {
        req.peer_addr().map(|socket| socket.ip())
    }

    /// The rightmost address in `X-Forwarded-For`, if present and parseable.
    fn forwarded_ip(req: &ServiceRequest) -> Option<IpAddr> {
        let value = req.headers().get(X_FORWARDED_FOR)?.to_str().ok()?;
        // Strictly the rightmost entry — the hop the trusted proxy appended.
        // Do not fall through to entries further left; those are client-supplied.
        value.rsplit(',').next()?.trim().parse::<IpAddr>().ok()
    }

    /// Match `PeerIpKeyExtractor`: rate-limit IPv6 per `/56` prefix, since a
    /// single customer is often handed a whole `/56`.
    fn normalize(ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V6(ipv6) => {
                let mut octets = ipv6.octets();
                octets[7..16].fill(0);
                IpAddr::V6(octets.into())
            }
            v4 => v4,
        }
    }
}

impl KeyExtractor for ClientIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        let ip = if self.trust_forwarded_for {
            Self::forwarded_ip(req).or_else(|| Self::peer_ip(req))
        } else {
            Self::peer_ip(req)
        };

        ip.map(Self::normalize).ok_or_else(|| {
            SimpleKeyExtractionError::new("Could not extract client IP address from request")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const PROXY: &str = "10.0.0.1:5000";

    fn extract(trust: bool, xff: Option<&str>, peer: &str) -> IpAddr {
        let mut req = TestRequest::default().peer_addr(peer.parse().unwrap());
        if let Some(xff) = xff {
            req = req.insert_header((X_FORWARDED_FOR, xff));
        }
        ClientIpKeyExtractor {
            trust_forwarded_for: trust,
        }
        .extract(&req.to_srv_request())
        .expect("key extraction failed")
    }

    #[test]
    fn peer_mode_ignores_forwarded_for() {
        // With trust disabled we always key on the peer, even if XFF is present.
        let ip = extract(false, Some("1.2.3.4"), PROXY);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn trusted_uses_single_forwarded_entry() {
        let ip = extract(true, Some("203.0.113.7"), PROXY);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[test]
    fn trusted_uses_rightmost_entry_not_spoofed_left() {
        // Client prepended a spoofed IP; the trusted proxy appended the real one
        // as the rightmost entry. We must key on the rightmost.
        let ip = extract(true, Some("6.6.6.6, 203.0.113.7"), PROXY);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[test]
    fn trusted_falls_back_to_peer_without_header() {
        let ip = extract(true, None, PROXY);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn trusted_falls_back_to_peer_on_unparseable_rightmost() {
        // A garbage rightmost entry must NOT cause us to walk left into the
        // spoofable client-supplied part; fall back to the peer instead.
        let ip = extract(true, Some("203.0.113.7, not-an-ip"), PROXY);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn ipv6_is_normalized_to_56_prefix() {
        let ip = extract(true, Some("2001:db8:abcd:ef00:1234:5678:9abc:def0"), PROXY);
        let expected = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0xabcd, 0xef00, 0, 0, 0, 0));
        assert_eq!(ip, expected);
    }
}
