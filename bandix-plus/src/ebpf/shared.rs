use aya::programs::{LinkOrder, ProgramId};
use aya::programs::tc::{self, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType};
use log::debug;
use nix::sys::utsname;
use aya::maps::{HashMap, Map};
use aya::{Ebpf, Pod};
use bandix_plus_common::{
    DeviceGlobalLimitKey, DeviceIfaceLimitKey, DeviceTrafficKey, IfaceLimitKey,
    InterfaceTrafficKey, RateBucketValue, RateLimitValue, TrafficValue,
};
use serde::{Deserialize, Serialize};

use crate::options::{TcBackend, TcOrder};

pub const BANDIX_MAP_NAMES: [&str; 7] = [
    "IFACE_TRAFFIC_STATS", "DEVICE_TRAFFIC_STATS", "DEVICE_LIMIT_GLOBAL",
    "DEVICE_LIMIT_IFACE", "DEVICE_RATE_BUCKETS", "IFACE_LIMIT", "IFACE_RATE_BUCKETS",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpfMapStatus {
    pub name: String,
    pub id: u32,
    pub max_entries: u32,
    pub entries: u32,
    pub near_capacity: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BpfMapsSnapshot {
    pub configured_max_entries: u32,
    pub timestamp_ms: u64,
    pub maps: Vec<BpfMapStatus>,
    pub error: Option<String>,
}

fn describe_map<K: Pod, V: Pod>(ebpf: &Ebpf, name: &str) -> anyhow::Result<BpfMapStatus> {
    let map = ebpf.map(name).ok_or_else(|| anyhow::anyhow!("missing BPF map {name}"))?;
    let Map::HashMap(data) = map else { anyhow::bail!("{name} is not a hash map") };
    let info = data.info()?;
    let typed = HashMap::<_, K, V>::try_from(map)?;
    // Counts are approximate while traffic changes the map. Bound traversal even
    // if a concurrently removed key makes the kernel iterator restart.
    let entries = typed.keys().take(info.max_entries() as usize)
        .try_fold(0_u32, |count, key| key.map(|_| count + 1))?;
    Ok(BpfMapStatus {
        name: name.to_string(), id: info.id(), max_entries: info.max_entries(), entries,
        near_capacity: u64::from(entries) * 100 >= u64::from(info.max_entries()) * 80,
    })
}

pub fn bpf_maps_snapshot(ebpf: &Ebpf, configured_max_entries: u32) -> anyhow::Result<BpfMapsSnapshot> {
    Ok(BpfMapsSnapshot {
        configured_max_entries,
        timestamp_ms: crate::utils::time_utils::now_millis(),
        maps: vec![
            describe_map::<InterfaceTrafficKey, TrafficValue>(ebpf, "IFACE_TRAFFIC_STATS")?,
            describe_map::<DeviceTrafficKey, TrafficValue>(ebpf, "DEVICE_TRAFFIC_STATS")?,
            describe_map::<DeviceGlobalLimitKey, RateLimitValue>(ebpf, "DEVICE_LIMIT_GLOBAL")?,
            describe_map::<DeviceIfaceLimitKey, RateLimitValue>(ebpf, "DEVICE_LIMIT_IFACE")?,
            describe_map::<DeviceIfaceLimitKey, RateBucketValue>(ebpf, "DEVICE_RATE_BUCKETS")?,
            describe_map::<IfaceLimitKey, RateLimitValue>(ebpf, "IFACE_LIMIT")?,
            describe_map::<InterfaceTrafficKey, RateBucketValue>(ebpf, "IFACE_RATE_BUCKETS")?,
        ],
        error: None,
    })
}

/// 判断内核版本是否大于等于指定版本号
fn kernel_at_least(major: u32, minor: u32, patch: u32) -> bool {
    let s = match utsname::uname() {
        Ok(u) => u.release().to_string_lossy().into_owned(),
        Err(_) => return false,
    };
    let mut parts = s.splitn(3, |c: char| c == '.' || c == '-');
    let (maj, min, pat): (u32, u32, u32) = (
        parts.next().and_then(|p| p.parse().ok()).unwrap_or(0),
        parts.next().unwrap_or("0").parse().unwrap_or(0),
        parts
            .next()
            .unwrap_or("0")
            .split('-')
            .next()
            .unwrap_or("0")
            .parse()
            .unwrap_or(0),
    );
    (maj, min, pat) >= (major, minor, patch)
}

/// 解除 RLIMIT_MEMLOCK 限制以便加载 eBPF 程序
fn remove_rlimit_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedBackend {
    Tcx,
    Netlink,
}

/// 加载 eBPF 程序并挂载到指定网络接口的 ingress/egress
pub fn load_ebpf_programs(
    ifaces: &Vec<String>,
    tc_backend: TcBackend,
    tc_order: TcOrder,
    netlink_priority: Option<u16>,
    tcx_anchor_ingress_id: Option<u32>,
    tcx_anchor_egress_id: Option<u32>,
    bpf_map_max_entries: u32,
) -> anyhow::Result<Ebpf> {
    remove_rlimit_memlock();

    anyhow::ensure!((1024..=65536).contains(&bpf_map_max_entries), "BPF map capacity must be 1024..65536");
    let mut loader = aya::EbpfLoader::new();
    for name in BANDIX_MAP_NAMES {
        loader.map_max_entries(name, bpf_map_max_entries);
    }
    let mut ebpf = loader.load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/bandix-plus")))
        .map_err(|e: aya::EbpfError| anyhow::anyhow!("Failed to load eBPF program: {}", e))?;
    log::info!("BPF map capacity: {} entries in each of {} maps", bpf_map_max_entries, BANDIX_MAP_NAMES.len());

    // 把 eBPF 在内核中的日志，拉到用户态输出
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(_e) => {
            // This can happen if you remove all log statements from your eBPF program.
            // warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    for iface in ifaces.iter() {
        if let Err(e) = tc::qdisc_add_clsact(&iface) {
            log::debug!("Failed to add clsact qdisc (may already exist): {}", e);
        }
    }

    {
        let ingress_program: &mut SchedClassifier = ebpf
            .program_mut("bandix_plus_ingress")
            .ok_or_else(|| anyhow::anyhow!("bandix_plus_ingress program not found in eBPF object"))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| anyhow::anyhow!("Failed to convert ingress program to SchedClassifier: {:?}", e))?;
        ingress_program.load()?;
    }

    {
        let egress_program: &mut SchedClassifier = ebpf
            .program_mut("bandix_plus_egress")
            .ok_or_else(|| anyhow::anyhow!("bandix_plus_egress program not found in eBPF object"))?
            .try_into()
            .map_err(|e: aya::programs::ProgramError| anyhow::anyhow!("Failed to convert egress program to SchedClassifier: {:?}", e))?;
        egress_program.load()?;
    }

    let kernel_supports_tcx = kernel_at_least(6, 6, 0);
    let resolved_backend = match tc_backend {
        TcBackend::Auto => {
            if kernel_supports_tcx {
                ResolvedBackend::Tcx
            } else {
                ResolvedBackend::Netlink
            }
        }
        TcBackend::Tcx => {
            if !kernel_supports_tcx {
                anyhow::bail!("--tc-backend=tcx requires kernel >= 6.6.0");
            }
            ResolvedBackend::Tcx
        }
        TcBackend::Netlink => ResolvedBackend::Netlink,
    };

    if resolved_backend == ResolvedBackend::Tcx && netlink_priority.is_some() {
        anyhow::bail!("--netlink-priority is only valid for netlink backend");
    }

    if resolved_backend == ResolvedBackend::Netlink && matches!(tc_order, TcOrder::Before | TcOrder::After) {
        anyhow::bail!("--tc-order=before/after is not supported by netlink backend");
    }

    let ingress_anchor_program_id = tcx_anchor_ingress_id;
    let egress_anchor_program_id = tcx_anchor_egress_id;

    let opts = |attach_type: TcAttachType| -> anyhow::Result<TcAttachOptions> {
        match resolved_backend {
            ResolvedBackend::Tcx => {
                let anchor_program_id = match attach_type {
                    TcAttachType::Ingress => ingress_anchor_program_id,
                    TcAttachType::Egress => egress_anchor_program_id,
                    _ => None,
                };
                let order = match tc_order {
                    TcOrder::First => LinkOrder::first(),
                    TcOrder::Default => LinkOrder::default(),
                    TcOrder::Last => LinkOrder::last(),
                    TcOrder::Before => {
                        let id = anchor_program_id.ok_or_else(|| {
                            anyhow::anyhow!(
                                "anchor program id is required for {:?} when --tc-order=before; use --tcx-anchor-ingress-id/--tcx-anchor-egress-id",
                                attach_type
                            )
                        })?;
                        // SAFETY: program id validity is checked by kernel at attach time.
                        LinkOrder::before_program_id(unsafe { ProgramId::new(id) })
                    }
                    TcOrder::After => {
                        let id = anchor_program_id.ok_or_else(|| {
                            anyhow::anyhow!(
                                "anchor program id is required for {:?} when --tc-order=after; use --tcx-anchor-ingress-id/--tcx-anchor-egress-id",
                                attach_type
                            )
                        })?;
                        // SAFETY: program id validity is checked by kernel at attach time.
                        LinkOrder::after_program_id(unsafe { ProgramId::new(id) })
                    }
                };
                Ok(TcAttachOptions::TcxOrder(order))
            }
            ResolvedBackend::Netlink => {
                let nl_priority = if let Some(v) = netlink_priority {
                    v
                } else {
                    match tc_order {
                        TcOrder::First => 1u16,
                        TcOrder::Default => 0u16,
                        TcOrder::Last => 65535u16,
                        TcOrder::Before | TcOrder::After => {
                            anyhow::bail!("--tc-order=before/after is not supported by netlink backend");
                        }
                    }
                };
                Ok(TcAttachOptions::Netlink(NlOptions {
                    priority: nl_priority,
                    handle: 0,
                }))
            }
        }
    };

    for iface in ifaces {
        {
            let ingress_program: &mut SchedClassifier = ebpf
                .program_mut("bandix_plus_ingress")
                .ok_or_else(|| anyhow::anyhow!("bandix_plus_ingress program not found in eBPF object"))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| {
                    anyhow::anyhow!("Failed to convert ingress program to SchedClassifier: {:?}", e)
                })?;
            ingress_program.attach_with_options(
                iface,
                TcAttachType::Ingress,
                opts(TcAttachType::Ingress)?,
            )?;
        }
        {
            let egress_program: &mut SchedClassifier = ebpf
                .program_mut("bandix_plus_egress")
                .ok_or_else(|| anyhow::anyhow!("bandix_plus_egress program not found in eBPF object"))?
                .try_into()
                .map_err(|e: aya::programs::ProgramError| {
                    anyhow::anyhow!("Failed to convert egress program to SchedClassifier: {:?}", e)
                })?;
            egress_program.attach_with_options(
                iface,
                TcAttachType::Egress,
                opts(TcAttachType::Egress)?,
            )?;
        }
    }

    let order_str = match tc_order {
        TcOrder::First => "first",
        TcOrder::Default => "default",
        TcOrder::Last => "last",
        TcOrder::Before => "before",
        TcOrder::After => "after",
    };
    let backend_str = match resolved_backend {
        ResolvedBackend::Tcx => "tcx",
        ResolvedBackend::Netlink => "netlink",
    };
    let backend_req_str = match tc_backend {
        TcBackend::Auto => "auto",
        TcBackend::Tcx => "tcx",
        TcBackend::Netlink => "netlink",
    };
    log::info!(
        "Loading shared eBPF programs for interface [{}], order: {}, backend: {} (requested: {}), backend_options: {}",
        ifaces.join(","),
        order_str,
        backend_str,
        backend_req_str,
        match resolved_backend {
            ResolvedBackend::Tcx => format!(
                "tcx_anchor_ingress_id={},tcx_anchor_egress_id={}",
                tcx_anchor_ingress_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                tcx_anchor_egress_id
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ),
            ResolvedBackend::Netlink => format!(
                "netlink_priority={}",
                netlink_priority
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "derived_from_order".to_string())
            ),
        }
    );

    Ok(ebpf)
}
