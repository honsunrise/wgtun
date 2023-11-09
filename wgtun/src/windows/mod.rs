mod helper;

use std::mem::{align_of, size_of};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use std::{mem, ptr};

use anyhow::{bail, Context, Result};
use ffi::WireGuard;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tracing::{debug, error, info, warn};
use widestring::U16CStr;
use windows::core::{Error, GUID};
use windows::Win32::Foundation::{ERROR_MORE_DATA, ERROR_OBJECT_ALREADY_EXISTS};
use windows::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry,
    DeleteUnicastIpAddressEntry,
    FreeMibTable,
    GetIpInterfaceEntry,
    GetUnicastIpAddressTable,
    InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry,
    SetIpInterfaceEntry,
    MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{IpDadStatePreferred, ADDRESS_FAMILY, AF_INET, AF_INET6};

use self::helper::StructWriter;
use crate::implement::helper::StructReader;
use crate::{Interface, InterfaceDetail, PeerDetail};

/// A handle wrapper that allows it to be Send and Sync
#[derive(Clone)]
pub(crate) struct AdapterHandle(ffi::WIREGUARD_ADAPTER_HANDLE);

impl Into<ffi::WIREGUARD_ADAPTER_HANDLE> for AdapterHandle {
    fn into(self) -> ffi::WIREGUARD_ADAPTER_HANDLE {
        self.0
    }
}

unsafe impl Send for AdapterHandle {}
unsafe impl Sync for AdapterHandle {}

pub struct WireGuardNT {
    lib: Arc<WireGuard>,
    adapter: AdapterHandle,
}

impl Interface for WireGuardNT {
    fn up(&self) -> Result<()> {
        // the adapter luid
        let mut luid = NET_LUID_LH::default();
        unsafe {
            self.lib
                .WireGuardGetAdapterLUID(self.adapter.0, std::mem::transmute(&mut luid));
        }

        debug!("set adapter '{}' up", unsafe { luid.Value });
        let success = unsafe {
            self.lib.WireGuardSetAdapterState(
                self.adapter.0,
                ffi::WIREGUARD_ADAPTER_STATE_WIREGUARD_ADAPTER_STATE_UP,
            )
        } != 0;
        if !success {
            let err = Error::from_win32();
            bail!("call WireGuardSetAdapterState error: {err:#}");
        }
        Ok(())
    }

    fn down(&self) -> Result<()> {
        // the adapter luid
        let mut luid = NET_LUID_LH::default();
        unsafe {
            self.lib
                .WireGuardGetAdapterLUID(self.adapter.0, std::mem::transmute(&mut luid));
        }

        debug!("set adapter '{}' down", unsafe { luid.Value });
        let success = unsafe {
            self.lib.WireGuardSetAdapterState(
                self.adapter.0,
                ffi::WIREGUARD_ADAPTER_STATE_WIREGUARD_ADAPTER_STATE_DOWN,
            )
        } != 0;
        if !success {
            let err = Error::from_win32();
            bail!("call WireGuardSetAdapterState error: {err:#}");
        }
        Ok(())
    }

    fn set_link_ip_address(&self, ip: ipnet::IpNet, mtu: u32) -> Result<()> {
        // the adapter luid
        let mut luid = NET_LUID_LH::default();
        unsafe {
            self.lib
                .WireGuardGetAdapterLUID(self.adapter.0, std::mem::transmute(&mut luid));
        }

        debug!("current adapter luid: {:?}", unsafe { luid.Value });

        unsafe {
            // flush ip address for this interface
            debug!("flush current adapter '{}' ip", luid.Value);
            for family in [AF_INET, AF_INET6] {
                let mut unicast_ip_address_table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
                GetUnicastIpAddressTable(family, &mut unicast_ip_address_table as *mut _)
                    .context("list unicast ip address table")?;
                assert!(!unicast_ip_address_table.is_null());
                for i in 0..(*unicast_ip_address_table).NumEntries as usize {
                    let start =
                        &mut (*unicast_ip_address_table).Table[0] as *mut MIB_UNICASTIPADDRESS_ROW;
                    let unicast_ip_address_row = start.add(i);
                    if (*unicast_ip_address_row).InterfaceLuid.Value == luid.Value {
                        if let Err(err) = DeleteUnicastIpAddressEntry(unicast_ip_address_row) {
                            let _ = FreeMibTable(unicast_ip_address_table as *const _);
                            bail!("delete ip forward entry for interface: {err:#}")
                        }
                    }
                }
                let _ = FreeMibTable(unicast_ip_address_table as *const _);
            }

            // setup ip address
            debug!("setup current adapter '{}' ip", luid.Value);
            let mut address_row = MIB_UNICASTIPADDRESS_ROW::default();
            InitializeUnicastIpAddressEntry(&mut address_row);
            address_row.InterfaceLuid = luid;
            address_row.OnLinkPrefixLength = ip.prefix_len();
            address_row.DadState = IpDadStatePreferred;
            match ip {
                IpNet::V4(interface_addr_v4) => {
                    address_row.Address.Ipv4.sin_family = AF_INET;
                    address_row.Address.Ipv4.sin_addr =
                        std::mem::transmute(interface_addr_v4.addr().octets());
                },
                IpNet::V6(interface_addr_v6) => {
                    address_row.Address.Ipv6.sin6_family = AF_INET6;
                    address_row.Address.Ipv6.sin6_addr =
                        std::mem::transmute(interface_addr_v6.addr().octets());
                },
            }
            if let Err(err) = CreateUnicastIpAddressEntry(&address_row) {
                if err != ERROR_OBJECT_ALREADY_EXISTS.into() {
                    bail!("faild set ip for interface: {err:#}");
                }
            }

            let mut ip_interface = MIB_IPINTERFACE_ROW::default();
            InitializeIpInterfaceEntry(&mut ip_interface);
            ip_interface.InterfaceLuid = luid;
            ip_interface.Family = AF_INET;
            if let Err(err) = GetIpInterfaceEntry(&mut ip_interface) {
                bail!("faild get config for interface: {err:#}");
            }
            ip_interface.UseAutomaticMetric = false.into();
            ip_interface.Metric = 0;
            ip_interface.NlMtu = mtu;
            ip_interface.SitePrefixLength = 0;
            if let Err(err) = SetIpInterfaceEntry(&mut ip_interface) {
                bail!("faild set config for interface: {err:#}");
            }
            Ok(())
        }
    }

    fn get_detail(&self) -> Result<crate::InterfaceDetail> {
        let mut size = 0u32;
        let success = unsafe {
            self.lib
                .WireGuardGetConfiguration(self.adapter.0, std::ptr::null_mut(), &mut size as _)
                != 0
        };
        if !success {
            let err = Error::from_win32();
            if err != ERROR_MORE_DATA.into() {
                bail!("call WireGuardGetConfiguration error: {err:#}");
            }
        }

        let align = align_of::<ffi::WIREGUARD_INTERFACE>();
        let mut reader = StructReader::new(size as usize, align);
        let success = unsafe {
            self.lib
                .WireGuardGetConfiguration(self.adapter.0, reader.ptr() as _, &mut size as _)
                != 0
        };
        if !success {
            let err = Error::from_win32();
            bail!("call WireGuardGetConfiguration error: {err:#}");
        }

        let wireguard_interface: ffi::WIREGUARD_INTERFACE = unsafe { reader.read() };
        let mut interface_detail = InterfaceDetail {
            flags: wireguard_interface.Flags as u32,
            listen_port: wireguard_interface.ListenPort,
            private_key: wireguard_interface.PrivateKey,
            public_key: wireguard_interface.PublicKey,
            peers: Vec::with_capacity(wireguard_interface.PeersCount as usize),
        };

        let now = SystemTime::now();
        let now_instant = Instant::now();
        let unix_duration = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time set before unix epoch");

        const UNIX_EPOCH_FROM_1_1_1600: u64 = 116444736000000000;
        let now_since_1600 = UNIX_EPOCH_FROM_1_1_1600 + (unix_duration.as_nanos() / 100u128) as u64;

        for _ in 0..wireguard_interface.PeersCount {
            let peer: ffi::WIREGUARD_PEER = unsafe { reader.read() };
            let endpoint = peer.Endpoint;
            let address_family = ADDRESS_FAMILY(unsafe { endpoint.si_family });
            let endpoint = match address_family {
                AF_INET => {
                    let octets = unsafe { endpoint.Ipv4.sin_addr.S_un.S_un_b };
                    let address = Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4);
                    let port = u16::from_be(unsafe { endpoint.Ipv4.sin_port });
                    SocketAddr::V4(SocketAddrV4::new(address, port))
                },
                AF_INET6 => {
                    let octets = unsafe { endpoint.Ipv6.sin6_addr.u.Byte };
                    let address = Ipv6Addr::from(octets);
                    let port = u16::from_be(unsafe { endpoint.Ipv6.sin6_port });
                    let flow_info = unsafe { endpoint.Ipv6.sin6_flowinfo };
                    let scope_id = unsafe { endpoint.Ipv6.Anonymous.sin6_scope_id };
                    SocketAddr::V6(SocketAddrV6::new(address, port, flow_info, scope_id))
                },
                _ => {
                    panic!("Illegal address family {address_family:?}",);
                },
            };

            let handshake_delta = now_since_1600 - peer.LastHandshake;
            let last_handshake = now_instant
                .checked_sub(Duration::from_nanos(handshake_delta * 100))
                .unwrap_or_else(|| Instant::now());

            let mut peer_detail = PeerDetail {
                flags: peer.Flags as u32,
                public_key: peer.PublicKey,
                preshared_key: peer.PresharedKey,
                persistent_keepalive: peer.PersistentKeepalive,
                endpoint,
                tx_bytes: peer.TxBytes,
                rx_bytes: peer.RxBytes,
                last_handshake,
                allowed_ips: Vec::with_capacity(peer.AllowedIPsCount as usize),
            };
            for _ in 0..peer.AllowedIPsCount {
                let allowed_ip: ffi::WIREGUARD_ALLOWED_IP = unsafe { reader.read() };
                let prefix_length = allowed_ip.Cidr;
                let address_family = ADDRESS_FAMILY(allowed_ip.AddressFamily);
                let allowed_ip = match address_family {
                    AF_INET => {
                        let octets = unsafe { allowed_ip.Address.V4.as_ref().S_un.S_un_b };
                        let address =
                            Ipv4Addr::new(octets.s_b1, octets.s_b2, octets.s_b3, octets.s_b4);
                        IpNet::V4(Ipv4Net::new(address, prefix_length)?)
                    },
                    AF_INET6 => {
                        let octets = unsafe { allowed_ip.Address.V6.as_ref().u.Byte };
                        let address = Ipv6Addr::from(octets);
                        IpNet::V6(Ipv6Net::new(address, prefix_length)?)
                    },
                    _ => {
                        panic!("Illegal address family {address_family:?}");
                    },
                };
                peer_detail.allowed_ips.push(allowed_ip);
            }
            interface_detail.peers.push(peer_detail);
        }
        Ok(interface_detail)
    }

    fn update_private_key(&self, private_key: [u8; 32]) -> Result<()> {
        #[repr(C)]
        #[repr(align(8))]
        struct Config {
            interface: ffi::WIREGUARD_INTERFACE,
        }
        let config = Config {
            interface: ffi::WIREGUARD_INTERFACE {
                Flags: ffi::WIREGUARD_INTERFACE_FLAG_WIREGUARD_INTERFACE_HAS_PRIVATE_KEY,
                PrivateKey: private_key,
                ..Default::default()
            },
        };

        let success = unsafe {
            self.lib.WireGuardSetConfiguration(
                self.adapter.0,
                (&config as *const Config).cast(),
                size_of::<Config>() as u32,
            ) != 0
        };
        if !success {
            bail!(
                "call WireGuardSetConfiguration error: {:#}",
                Error::from_win32()
            );
        }
        Ok(())
    }

    fn get_public_key(&self) -> Result<[u8; 32]> {
        let detail = self.get_detail()?;
        Ok(detail.public_key)
    }

    fn update_listen_port(&self, port: u16) -> Result<()> {
        #[repr(C)]
        #[repr(align(8))]
        struct Config {
            interface: ffi::WIREGUARD_INTERFACE,
        }
        let config = Config {
            interface: ffi::WIREGUARD_INTERFACE {
                Flags: ffi::WIREGUARD_INTERFACE_FLAG_WIREGUARD_INTERFACE_HAS_LISTEN_PORT,
                ListenPort: port,
                ..Default::default()
            },
        };

        let success = unsafe {
            self.lib.WireGuardSetConfiguration(
                self.adapter.0,
                (&config as *const Config).cast(),
                size_of::<Config>() as u32,
            ) != 0
        };
        if !success {
            bail!(
                "call WireGuardSetConfiguration error: {:#}",
                Error::from_win32()
            );
        }
        Ok(())
    }

    fn upsert_peer(&self, peer: crate::PeerConfig) -> Result<()> {
        let size = size_of::<ffi::WIREGUARD_INTERFACE>()
            + size_of::<ffi::WIREGUARD_PEER>()
            + peer.allowed_ips.len() * size_of::<ffi::WIREGUARD_ALLOWED_IP>();
        let align = align_of::<ffi::WIREGUARD_INTERFACE>();

        let mut writer = StructWriter::new(size, align);

        let ffi_interface: &mut ffi::WIREGUARD_INTERFACE = unsafe { writer.write() };
        ffi_interface.PeersCount = 1;

        let ffi_peer: &mut ffi::WIREGUARD_PEER = unsafe { writer.write() };
        ffi_peer.PublicKey = peer.public_key;
        ffi_peer.Flags = ffi::WIREGUARD_PEER_FLAG_WIREGUARD_PEER_HAS_ENDPOINT
            | ffi::WIREGUARD_PEER_FLAG_WIREGUARD_PEER_HAS_PUBLIC_KEY;
        match peer.endpoint {
            SocketAddr::V4(v4) => {
                let addr = unsafe { std::mem::transmute(v4.ip().octets()) };
                ffi_peer.Endpoint.Ipv4.sin_family = AF_INET.0 as u16;
                ffi_peer.Endpoint.Ipv4.sin_port = u16::from_ne_bytes(v4.port().to_be_bytes());
                ffi_peer.Endpoint.Ipv4.sin_addr = addr;
            },
            SocketAddr::V6(v6) => {
                let addr = unsafe { std::mem::transmute(v6.ip().octets()) };
                ffi_peer.Endpoint.Ipv6.sin6_family = AF_INET6.0 as u16;
                ffi_peer.Endpoint.Ipv6.sin6_port = u16::from_ne_bytes(v6.port().to_be_bytes());
                ffi_peer.Endpoint.Ipv6.sin6_addr = addr;
            },
        }
        if let Some(preshared_key) = peer.preshared_key {
            ffi_peer.Flags |= ffi::WIREGUARD_PEER_FLAG_WIREGUARD_PEER_HAS_PRESHARED_KEY;
            ffi_peer.PresharedKey = preshared_key;
        }
        if let Some(keep_alive) = peer.keep_alive {
            ffi_peer.Flags |= ffi::WIREGUARD_PEER_FLAG_WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE;
            ffi_peer.PersistentKeepalive = keep_alive;
        }
        ffi_peer.AllowedIPsCount = peer.allowed_ips.len() as u32;
        for allowed_ip in &peer.allowed_ips {
            // Safety:
            // Same as above, `writer` is aligned because it was aligned before
            let wg_allowed_ip: &mut ffi::WIREGUARD_ALLOWED_IP = unsafe { writer.write() };
            match allowed_ip {
                IpNet::V4(v4) => {
                    let addr = unsafe { std::mem::transmute(v4.addr().octets()) };
                    unsafe { *wg_allowed_ip.Address.V4.as_mut() = addr };
                    wg_allowed_ip.AddressFamily = AF_INET.0 as u16;
                    wg_allowed_ip.Cidr = v4.prefix_len();
                },
                IpNet::V6(v6) => {
                    let addr = unsafe { std::mem::transmute(v6.addr().octets()) };
                    unsafe { *wg_allowed_ip.Address.V6.as_mut() = addr };
                    wg_allowed_ip.AddressFamily = AF_INET6.0 as u16;
                    wg_allowed_ip.Cidr = v6.prefix_len();
                },
            }
        }

        let success = unsafe {
            self.lib
                .WireGuardSetConfiguration(self.adapter.0, writer.ptr().cast(), size as u32)
                != 0
        };
        if !success {
            bail!(
                "call WireGuardSetConfiguration error: {:#}",
                Error::from_win32()
            );
        }
        Ok(())
    }

    fn remove_peer(&self, public_key: [u8; 32]) -> Result<()> {
        #[repr(C)]
        #[repr(align(8))]
        struct Config {
            interface: ffi::WIREGUARD_INTERFACE,
            peer: ffi::WIREGUARD_PEER,
        }
        let config = Config {
            interface: ffi::WIREGUARD_INTERFACE {
                PeersCount: 1,
                ..Default::default()
            },
            peer: ffi::WIREGUARD_PEER {
                Flags: ffi::WIREGUARD_PEER_FLAG_WIREGUARD_PEER_REMOVE,
                PublicKey: public_key,
                ..Default::default()
            },
        };

        let success = unsafe {
            self.lib.WireGuardSetConfiguration(
                self.adapter.0,
                (&config as *const Config).cast(),
                size_of::<Config>() as u32,
            ) != 0
        };
        if !success {
            bail!(
                "call WireGuardSetConfiguration error: {:#}",
                Error::from_win32()
            );
        }
        Ok(())
    }

    fn clear_peers(&self) -> Result<()> {
        #[repr(C)]
        #[repr(align(8))]
        struct Config {
            interface: ffi::WIREGUARD_INTERFACE,
        }
        let config = Config {
            interface: ffi::WIREGUARD_INTERFACE {
                Flags: ffi::WIREGUARD_INTERFACE_FLAG_WIREGUARD_INTERFACE_REPLACE_PEERS,
                PeersCount: 0,
                ..Default::default()
            },
        };

        let success = unsafe {
            self.lib.WireGuardSetConfiguration(
                self.adapter.0,
                (&config as *const Config).cast(),
                size_of::<Config>() as u32,
            ) != 0
        };
        if !success {
            bail!(
                "call WireGuardSetConfiguration error: {:#}",
                Error::from_win32()
            );
        }
        Ok(())
    }
}

impl Drop for WireGuardNT {
    fn drop(&mut self) {
        let adapter = mem::replace(&mut self.adapter, AdapterHandle(ptr::null_mut()));
        unsafe {
            self.lib.WireGuardCloseAdapter(adapter.into());
        }
    }
}

pub extern "C" fn default_logger(
    level: ffi::WIREGUARD_LOGGER_LEVEL,
    _timestamp: u64,
    message: *const u16,
) {
    if message.is_null() {
        return;
    }
    let msg = unsafe { U16CStr::from_ptr_str(message) };
    let utf8_msg = msg.to_string_lossy();
    match level {
        ffi::WIREGUARD_LOGGER_LEVEL_WIREGUARD_LOG_INFO => {
            info!("wireguard-nt: {}", utf8_msg)
        },
        ffi::WIREGUARD_LOGGER_LEVEL_WIREGUARD_LOG_WARN => {
            warn!("wireguard-nt: {}", utf8_msg)
        },
        ffi::WIREGUARD_LOGGER_LEVEL_WIREGUARD_LOG_ERR => {
            error!("wireguard-nt: {}", utf8_msg)
        },
        _ => {
            error!("wireguard-nt[invalid log level({})]: {}", level, utf8_msg,)
        },
    }
}

static INIT: OnceLock<Arc<WireGuard>> = OnceLock::new();

pub fn init<P: AsRef<Path>>(lib_path: P) -> Result<()> {
    let path = lib_path.as_ref();
    INIT.get_or_try_init(|| -> Result<Arc<WireGuard>> {
        Ok(Arc::new(unsafe { WireGuard::new(path) }?))
    })?;
    Ok(())
}

pub fn create_interface<N: AsRef<str>>(name: N) -> Result<impl Interface> {
    let name = name.as_ref();

    let Some(wireguard) = INIT.get() else {
        bail!("please call init first");
    };

    unsafe { wireguard.WireGuardSetLogger(Some(default_logger)) };

    let name_utf16 = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let pool_utf16 = format!("{name}Pool")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let guid = GUID::new()?;

    let adapter = unsafe {
        let guid = windows_sys::core::GUID {
            data1: guid.data1,
            data2: guid.data2,
            data3: guid.data3,
            data4: guid.data4,
        };
        wireguard.WireGuardCreateAdapter(pool_utf16.as_ptr(), name_utf16.as_ptr(), &guid)
    };
    if adapter.is_null() {
        return Err(Error::from_win32().into());
    }

    Ok(WireGuardNT {
        lib: Arc::clone(wireguard),
        adapter: AdapterHandle(adapter),
    })
}

pub fn open_interface<N: AsRef<str>>(name: N) -> Result<impl Interface> {
    let name = name.as_ref();

    let Some(wireguard) = INIT.get() else {
        bail!("please call init first");
    };

    let name_utf16 = name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let adapter = unsafe { wireguard.WireGuardOpenAdapter(name_utf16.as_ptr()) };
    if adapter.is_null() {
        return Err(Error::from_win32().into());
    }

    Ok(WireGuardNT {
        lib: Arc::clone(wireguard),
        adapter: AdapterHandle(adapter),
    })
}
