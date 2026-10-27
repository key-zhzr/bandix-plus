use clap::Parser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcOrder {
    First,
    Default,
    Last,
    Before,
    After,
}

impl TcOrder {
    /// 将字符串解析为 TC 挂载顺序枚举。
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "first" => Some(Self::First),
            "default" => Some(Self::Default),
            "last" => Some(Self::Last),
            "before" => Some(Self::Before),
            "after" => Some(Self::After),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcBackend {
    Auto,
    Tcx,
    Netlink,
}

impl TcBackend {
    /// 将字符串解析为 TC 挂载后端枚举。
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "tcx" => Some(Self::Tcx),
            "netlink" => Some(Self::Netlink),
            _ => None,
        }
    }
}

#[derive(Parser, Debug, Clone)]
#[command(about = "Network traffic monitoring based on eBPF for OpenWrt")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "https://github.com/timsaya")]
pub struct Options {
    #[arg(
        long,
        default_value_t = false,
        help = "Enable traffic collection and service startup (set false to exit immediately)"
    )]
    pub enable_traffic: bool,

    #[arg(
        long = "traffic_enable_storage",
        default_value_t = false,
        help = "Enable persistent storage for traffic history data (default: false)"
    )]
    pub traffic_enable_storage: bool,

    #[arg(
        long = "traffic-retention-days",
        default_value_t = 366,
        help = "Days of hourly traffic buckets to keep in SQLite when storage is enabled (0 = keep forever)"
    )]
    pub traffic_retention_days: u32,

    #[arg(
        long = "bpf-map-max-entries",
        default_value_t = 65536,
        value_parser = clap::value_parser!(u32).range(1024..=65536),
        help = "Capacity of each BPF traffic/limit map (1024..65536); changing it requires a service restart"
    )]
    pub bpf_map_max_entries: u32,

    #[arg(short, long, help = "Network interface to monitor (can specify multiple times)")]
    pub iface: Vec<String>,

    #[arg(
        long,
        default_value = "info",
        help = "Log level: trace, debug, info, warn, error (default: info)"
    )]
    pub log_level: String,

    #[arg(long, default_value = "default", help = "TC order: first, default, last, before, after")]
    pub tc_order: String,

    #[arg(
        long,
        default_value = "auto",
        help = "TC attach backend: auto, tcx, netlink (default: auto)"
    )]
    pub tc_backend: String,

    #[arg(
        long = "netlink-priority",
        help = "Netlink priority (0..65535, 0 means default). Only used when netlink backend is active"
    )]
    pub netlink_priority: Option<u16>,

    #[arg(
        long = "tcx-anchor-ingress-id",
        help = "TCX ingress anchor program id. Used when tc-order is before/after"
    )]
    pub tcx_anchor_ingress_id: Option<u32>,

    #[arg(
        long = "tcx-anchor-egress-id",
        help = "TCX egress anchor program id. Used when tc-order is before/after"
    )]
    pub tcx_anchor_egress_id: Option<u32>,

    #[arg(
        long,
        default_value_t = 10,
        help = "Traffic history window in minutes (default: 10)"
    )]
    pub history_window_minutes: u32,

    #[arg(long, default_value = "127.0.0.1", help = "Server bind host")]
    pub host: String,

    #[arg(long, default_value_t = 8787, help = "Server bind port")]
    pub port: u16,

    #[arg(
        long,
        default_value = "/usr/share/bandix-plus",
        help = "Data directory for persisted policy/devices and optional traffic history data"
    )]
    pub data_dir: String,
}

#[cfg(test)]
mod tests {
    use super::{Options, TcBackend, TcOrder};
    use clap::Parser;

    #[test]
    fn bpf_capacity_defaults_and_boundaries() {
        assert_eq!(Options::try_parse_from(["bandix-plus"]).unwrap().bpf_map_max_entries, 65536);
        for value in ["1024", "4096", "8192", "65536"] {
            let options = Options::try_parse_from(["bandix-plus", "--bpf-map-max-entries", value]).unwrap();
            assert_eq!(options.bpf_map_max_entries.to_string(), value);
        }
        for value in ["0", "1023", "65537", "4294967296", "-1", "invalid"] {
            assert!(Options::try_parse_from(["bandix-plus", "--bpf-map-max-entries", value]).is_err());
        }
    }

    #[test]
    fn tc_order_parse_first() {
        assert_eq!(TcOrder::parse("first"), Some(TcOrder::First));
        assert_eq!(TcOrder::parse("FIRST"), Some(TcOrder::First));
    }

    #[test]
    fn tc_order_parse_default() {
        assert_eq!(TcOrder::parse("default"), Some(TcOrder::Default));
    }

    #[test]
    fn tc_order_parse_last() {
        assert_eq!(TcOrder::parse("last"), Some(TcOrder::Last));
    }

    #[test]
    fn tc_order_parse_before() {
        assert_eq!(TcOrder::parse("before"), Some(TcOrder::Before));
    }

    #[test]
    fn tc_order_parse_after() {
        assert_eq!(TcOrder::parse("after"), Some(TcOrder::After));
    }

    #[test]
    fn tc_order_parse_invalid() {
        assert_eq!(TcOrder::parse("invalid"), None);
    }

    #[test]
    fn tc_backend_parse_auto() {
        assert_eq!(TcBackend::parse("auto"), Some(TcBackend::Auto));
        assert_eq!(TcBackend::parse("AUTO"), Some(TcBackend::Auto));
    }

    #[test]
    fn tc_backend_parse_tcx() {
        assert_eq!(TcBackend::parse("tcx"), Some(TcBackend::Tcx));
    }

    #[test]
    fn tc_backend_parse_netlink() {
        assert_eq!(TcBackend::parse("netlink"), Some(TcBackend::Netlink));
    }

    #[test]
    fn tc_backend_parse_invalid() {
        assert_eq!(TcBackend::parse("invalid"), None);
    }
}
