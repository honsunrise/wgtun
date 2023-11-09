use std::env;
use std::path::PathBuf;

use bindgen::RustTarget;

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());

    const HEADER_CONTENTS: &str = r#"
#include "wireguard.h"

WIREGUARD_CREATE_ADAPTER_FUNC WireGuardCreateAdapter;
WIREGUARD_OPEN_ADAPTER_FUNC WireGuardOpenAdapter;
WIREGUARD_CLOSE_ADAPTER_FUNC WireGuardCloseAdapter;
WIREGUARD_GET_ADAPTER_LUID_FUNC WireGuardGetAdapterLUID;
WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC WireGuardGetRunningDriverVersion;
WIREGUARD_DELETE_DRIVER_FUNC WireGuardDeleteDriver;
WIREGUARD_SET_LOGGER_FUNC WireGuardSetLogger;
WIREGUARD_SET_ADAPTER_LOGGING_FUNC WireGuardSetAdapterLogging;
WIREGUARD_GET_ADAPTER_STATE_FUNC WireGuardGetAdapterState;
WIREGUARD_SET_ADAPTER_STATE_FUNC WireGuardSetAdapterState;
WIREGUARD_GET_CONFIGURATION_FUNC WireGuardGetConfiguration;
WIREGUARD_SET_CONFIGURATION_FUNC WireGuardSetConfiguration;
"#;

    const RAW_LINE: &str = r#"
use ::windows_sys::core::*;
use ::windows_sys::Win32::Networking::WinSock::{ADDRESS_FAMILY, SOCKADDR_INET, IN_ADDR, IN6_ADDR};
use ::windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use ::windows_sys::Win32::Foundation::BOOL;

type NET_LUID = NET_LUID_LH;
type LPCWSTR = PCWSTR;
type DWORD64 = u64;
type BYTE = u8;
type DWORD = u32;
type WORD = u16;
"#;

    bindgen::builder()
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .rust_target(RustTarget::Stable_1_71)
        .dynamic_library_name("WireGuard")
        .dynamic_link_require_all(true)
        .raw_line(RAW_LINE)
        .header_contents("wrapper.h", HEADER_CONTENTS)
        .clang_arg("-I")
        .clang_arg(manifest_dir.join("src").as_os_str().to_str().unwrap())
        .layout_tests(false)
        .derive_default(true)
        .blocklist_type("wchar_t")
        .blocklist_type("BOOL")
        .blocklist_type("ULONG")
        .blocklist_type("USHORT")
        .blocklist_type("UCHAR")
        .blocklist_type("DWORD")
        .blocklist_type("BYTE")
        .blocklist_type("WORD")
        .blocklist_type("ULONG64")
        .blocklist_type("DWORD64")
        .blocklist_type("CHAR")
        .blocklist_type("WCHAR")
        .blocklist_type("LPCWSTR")
        .blocklist_type("in_addr")
        .blocklist_type("in_addr_.*")
        .blocklist_type("IN_ADDR")
        .blocklist_type("in6_addr")
        .blocklist_type("in6_addr_.*")
        .blocklist_type("IN6_ADDR")
        .blocklist_type("sockaddr_in4")
        .blocklist_type("sockaddr_in4_.*")
        .blocklist_type("SOCKADDR_IN4_LH")
        .blocklist_type("SOCKADDR_IN4")
        .blocklist_type("sockaddr_in6")
        .blocklist_type("sockaddr_in6_.*")
        .blocklist_type("SOCKADDR_IN6_LH")
        .blocklist_type("SOCKADDR_IN6")
        .blocklist_type("_SOCKADDR_INET")
        .blocklist_type("SOCKADDR_INET")
        .blocklist_type("sockaddr_in")
        .blocklist_type("SOCKADDR_IN")
        .blocklist_type("_NET_LUID_LH")
        .blocklist_type("_NET_LUID_LH_.*")
        .blocklist_type("NET_LUID_LH")
        .blocklist_type("NET_LUID")
        .blocklist_type("_GUID")
        .blocklist_type("GUID")
        .blocklist_type("ADDRESS_FAMILY")
        .blocklist_type("SCOPE_ID")
        .blocklist_type("SCOPE_ID_.*")
        .allowlist_function("WireGuard.*")
        .allowlist_type("WIREGUARD_.*")
        .generate()
        .unwrap()
        .write_to_file(out_dir.join("bindings.rs"))
        .unwrap();
}
