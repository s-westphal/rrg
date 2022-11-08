// Copyright 2020 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

//! A handler and associated types for the interfaces action.
//!
//! The interfaces action lists all network interfaces available on the client,
//! collecting their names, MAC and IP addresses.

use rrg_macro::warn;

use crate::session::{self, Session};

/// A response type for the interfaces action.
#[derive(Debug)]
pub struct Response {
    /// Information about an interface.
    interface: crate::net::Interface,
}

/// Handles requests for the interfaces action.
pub fn handle<S: Session>(session: &mut S, _: ()) -> session::Result<()> {
    let interfaces = crate::net::interfaces()
        .map_err(crate::session::Error::action)?;

    for interface in interfaces {
        session.reply(Response {
            interface: interface,
        })?;
    }

    Ok(())
}

impl super::Item for Response {

    const RDF_NAME: &'static str = "Interface";

    type Proto = rrg_proto::jobs::Interface;

    fn into_proto(self) -> rrg_proto::jobs::Interface {
        let mut proto = rrg_proto::jobs::Interface::new();

        let name = self.interface.name().to_string_lossy();
        if let std::borrow::Cow::Owned(_) = &name {
            warn!("network interface name with invalid bytes: {:?}", name);
        }
        proto.set_ifname(name.to_string());

        if let Some(mac_addr) = self.interface.mac_addr() {
            proto.set_mac_address(mac_addr.octets().into());
        } else {
            warn!("network interface '{}' without MAC address", name);
        }

        for ip_addr in self.interface.ip_addrs() {
            use rrg_proto::jobs::NetworkAddress_Family::{INET, INET6};

            let mut ip_addr_proto = rrg_proto::jobs::NetworkAddress::new();
            match ip_addr {
                std::net::IpAddr::V4(ip_addr) => {
                    ip_addr_proto.set_address_type(INET);
                    ip_addr_proto.set_packed_bytes(ip_addr.octets().into());
                },
                std::net::IpAddr::V6(ip_addr) => {
                    ip_addr_proto.set_address_type(INET6);
                    ip_addr_proto.set_packed_bytes(ip_addr.octets().into());
                },
            };
            proto.mut_addresses().push(ip_addr_proto);
        }

        proto
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn loopback_exists() {
        let mut session = session::FakeSession::new();
        assert!(handle(&mut session, ()).is_ok());

        // We have a choice: either require any of the addresses to be the loop-
        // back address or require all of them for it to be considered loopback.
        // Both of these options feel equally wrong and equally right but the
        // former one will return `true` for interfaces with no known addresses.
        // Since this feels awkward, we lean towards the "all" option.
        fn is_loopback(iface: &crate::net::Interface) -> bool {
            iface.ip_addrs().iter().all(std::net::IpAddr::is_loopback)
        }

        assert! {
            session.replies().any(|reply: &Response| {
                is_loopback(&reply.interface)
            })
        }
    }
}
