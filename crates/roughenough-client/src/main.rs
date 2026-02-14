//! The main client CLI

use std::net::ToSocketAddrs;
use std::time::Duration;

use clap::Parser;
use jiff::Timestamp;
use jiff::tz::TimeZone;
use roughenough_client::ClientError::DnsLookupFailed;
use roughenough_client::args::Args;
use roughenough_client::measurement::Measurement;
use roughenough_client::reporting::MalfeasanceReport;
use roughenough_client::sequence::MeasurementSequence;
use roughenough_client::server_list::ServerList;
use roughenough_client::{CausalityViolation, Client, ResponseValidator, server_list};
use roughenough_common::encoding::try_decode_key;
use roughenough_protocol::tag::Tag;
use tracing::{debug, error, info, warn};

#[derive(thiserror::Error, Debug)]
enum CliError {
    #[error("{0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Client(#[from] roughenough_client::ClientError),

    #[error("{0}")]
    ServerList(#[from] server_list::Error),

    #[error("{0}")]
    Decode(#[from] data_encoding::DecodeError),
}

fn main() {
    let args = Args::parse();

    enable_logging(&args);
    debug!("command line: {:?}", args);

    let midpoint = match (&args.hostname, &args.server_list) {
        // Simple case, query a single server
        (Some(hostname), None) => query_single_server(&args, hostname),
        // Measurement sequence of multiple servers
        (None, Some(list_file)) => query_multiple_servers(&args, list_file),
        _ => {
            error!(
                "Specify 'hostname' and 'port', or use '--server-list' to query multiple servers (see --help for details)"
            );
            std::process::exit(-1);
        }
    };

    if args.set_clock {
        set_system_clock(midpoint);
    };
}

fn query_single_server(args: &Args, hostname: &String) -> u64 {
    let port = args.port.unwrap();
    let host_port = format!("{hostname}:{port}");
    let sock_addr = host_port
        .to_socket_addrs()
        .unwrap_or_else(|e| {
            error!("Error resolving '{host_port}': {e}");
            std::process::exit(-1);
        })
        .next()
        .unwrap_or_else(|| {
            error!("Could not find IP address for '{host_port}'");
            std::process::exit(-1);
        });

    let mut builder = Client::builder(sock_addr)
        .hostname(hostname)
        .timeout(Duration::from_secs(args.timeout as u64))
        .protocol_version(args.protocol_version());

    if let Some(encoded_key) = &args.pub_key {
        let pub_key = try_decode_key(encoded_key).unwrap_or_else(|e| {
            error!("Error decoding public key: {e}");
            std::process::exit(-1);
        });
        builder = builder.public_key(pub_key);
    }

    let client = builder.build();

    let mut midpoint: u64 = 0;
    for _ in 0..args.num_requests {
        let (result, request_bytes, response_bytes) = client.query_raw().unwrap_or_else(|e| {
            error!("Failed to reach '{hostname}:{port}': {e}");
            std::process::exit(-1);
        });

        if args.dump_console {
            dump_raw_frame(&request_bytes, "Request dump");
            println!();
            dump_raw_frame(&response_bytes, "Response dump");
            println!();
        }

        let measurement = result.unwrap_or_else(|e| {
            error!("Validation failed for '{hostname}:{port}': {e}");
            std::process::exit(-1);
        });

        display_measurement(args, &measurement);
        midpoint = measurement.midpoint();
    }

    midpoint
}

fn query_multiple_servers(args: &Args, list_file: &String) -> u64 {
    let server_list = ServerList::from_file(list_file).unwrap_or_else(|e| {
        error!("Loading server list from '{list_file}': {e}");
        std::process::exit(-1);
    });

    let max_attempts = 1 + args.causality_violation_retries;
    let mut last_midpoint: u64 = 0;

    for attempt in 1..=max_attempts {
        let clients = clients_from_list(&server_list, args).unwrap_or_else(|e| {
            error!("Processing '{list_file}': {e}");
            std::process::exit(-1);
        });

        let mut sequence = MeasurementSequence::new(clients).unwrap_or_else(|e| {
            error!("Invalid measurement sequence: {e}");
            std::process::exit(-1);
        });

        let measurements = sequence
            .run(args.num_measurement_rounds)
            .unwrap_or_else(|e| {
                error!("Could not complete measurement sequence: {e}");
                std::process::exit(-1);
            });

        last_midpoint = measurements.last().unwrap().midpoint();
        let violations = ResponseValidator::validate_causality(&measurements);

        if violations.is_empty() {
            return last_midpoint;
        }

        // Violations detected - alert user and optionally send reports
        for violation in &violations {
            display_violation(args, violation);
        }

        if args.send_report
            && let Some(report_url) = server_list.reporting_url()
        {
            for violation in &violations {
                let report = MalfeasanceReport::from_violation(violation);
                if let Err(e) = report.submit(report_url, args.report_timeout, args.report_retries)
                {
                    error!("Failed to send malfeasance report: {e}");
                }
            }
        }

        // Retry if attempts remaining (RFC 8.2: "make another measurement")
        if attempt < max_attempts {
            warn!(
                "Causality violation detected, retrying measurement ({}/{})",
                attempt, args.causality_violation_retries
            );
        } else if args.causality_violation_retries > 0 {
            error!(
                "Causality violations persisted after {} retries",
                args.causality_violation_retries
            );
        }
    }

    // All attempts had violations
    if args.allow_untrusted_time {
        warn!("Returning untrusted time due to --allow-untrusted-time flag");
        return last_midpoint;
    }

    std::process::exit(1);
}

fn set_system_clock(midpoint: u64) {
    assert!(
        midpoint > 1_500_000_000,
        "not setting clock to suspicious midpoint: {midpoint}"
    );

    let spec = libc::timespec {
        tv_sec: midpoint as libc::time_t,
        tv_nsec: 0,
    };

    let spec_ptr = &spec as *const libc::timespec;
    let ret = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, spec_ptr) };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        error!("Failed to set system clock: {}", err);
    }
}

fn enable_logging(args: &Args) {
    let mut builder = tracing_subscriber::fmt().compact();

    if args.quiet {
        builder = builder.with_max_level(tracing::Level::ERROR);
    } else {
        match args.verbose {
            2.. => builder = builder.with_max_level(tracing::Level::TRACE),
            1 => builder = builder.with_max_level(tracing::Level::DEBUG),
            _ => builder = builder.with_max_level(tracing::Level::INFO),
        }
    }

    builder.init();
}

fn clients_from_list(server_list: &ServerList, args: &Args) -> Result<Vec<Client>, CliError> {
    let target_servers = server_list.choose_random(args.num_unique_servers)?;

    let chosen_ones = target_servers
        .iter()
        .map(|s| s.name())
        .collect::<Vec<_>>()
        .join(", ");

    debug!(
        "Loaded {} servers; chosen: {}",
        server_list.servers().len(),
        chosen_ones
    );

    let timeout = Duration::from_secs(args.timeout as u64);
    let mut clients = Vec::new();

    for server in target_servers {
        // resolve the address
        let host = server.first_address().host();
        let port = server.first_address().port();
        let addr_str = format!("{host}:{port}");
        let sock_addr = addr_str
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| DnsLookupFailed(host.to_string()))?;

        let encoded_key = server.public_key();
        let public_key = try_decode_key(encoded_key)?;

        // Build client with all settings
        let client = Client::builder(sock_addr)
            .hostname(server.name())
            .timeout(timeout)
            .public_key(public_key)
            .protocol_version(server.protocol_version())
            .build();

        clients.push(client);
    }

    Ok(clients)
}

// You might read this and think "can any other types of violation occur?"
//
// The Roughtime protocol defines exactly one causality constraint:
//   * For measurements i and j, where i was received before j:
//     MIDP[i] - RADI[i] <= MIDP[j] + RADI[j]
//
// This translates to: the earliest possible time of measurement i must be less than or equal to the
// latest possible time of measurement j.
//
// There are no other causality violations in Roughtime because:
//   1. Overlapping intervals are allowed - As long as the causality constraint is satisfied, time
//      intervals can overlap
//   2. Midpoints don't need to be monotonic - M1's midpoint can be after M2's midpoint, as long as
//      their intervals satisfy causality
//   3. No other temporal constraints - The protocol doesn't impose any other time-ordering
//      requirements
//
fn display_violation(args: &Args, violation: &CausalityViolation) {
    let m1 = &violation.measurement_i;
    let m2 = &violation.measurement_j;

    let m1_lower = m1.midpoint() - m1.radius() as u64;
    let m2_upper = m2.midpoint() + m2.radius() as u64;

    let m1_lower_dt = Timestamp::from_second(m1_lower as i64).unwrap();
    let m1_midpoint_dt = Timestamp::from_second(m1.midpoint() as i64).unwrap();
    let m2_upper_dt = Timestamp::from_second(m2_upper as i64).unwrap();
    let m2_midpoint_dt = Timestamp::from_second(m2.midpoint() as i64).unwrap();

    error!("=== Causality violation ===");
    error!("");
    error!("Measurement A (requested first from {}):", m1.hostname());
    error!("  Server:   {}", m1.server());
    error!(
        "  Time:     {} +/- {}s",
        m1_midpoint_dt.strftime(&args.time_format),
        m1.radius()
    );
    error!("  Earliest: {}", m1_lower_dt.strftime(&args.time_format));
    error!("");
    error!("Measurement B (requested second from {}):", m2.hostname());
    error!("  Server:   {}", m2.server());
    error!(
        "  Time:     {} +/- {}s",
        m2_midpoint_dt.strftime(&args.time_format),
        m2.radius()
    );
    error!("  Latest:   {}", m2_upper_dt.strftime(&args.time_format));
    error!("");
    error!(
        "Problem: A earliest ({}) > B latest ({})",
        m1_lower_dt.strftime("%H:%M:%S"),
        m2_upper_dt.strftime("%H:%M:%S")
    );

    if m1.server() == m2.server() {
        error!(
            "Note: Both measurements are from the SAME server - suggesting an issue with the server and/or its clock"
        );
    }
    error!("===========================");
}

fn display_measurement(args: &Args, measurement: &Measurement) {
    let midpoint = measurement.midpoint();
    let radius = measurement.radius();
    let timestamp = Timestamp::from_second(midpoint as i64).unwrap();

    let output = match (args.zulu, args.epoch) {
        (true, false) => format!("{} (+/-{}s)", timestamp.strftime(&args.time_format), radius),
        (false, false) => {
            let local_time = timestamp.to_zoned(TimeZone::system());
            format!(
                "{} (+/-{}s)",
                local_time.strftime(&args.time_format),
                radius
            )
        }
        (_, true) => format!("{}", timestamp.as_second()),
    };

    info!("{}", output);
}

/// Parsed raw frame info for protocol debugging.
/// Used for both requests and responses since they share the same wire format.
#[derive(Debug)]
struct RawFrameInfo {
    magic: [u8; 8],
    frame_length: u32,
    num_tags: u32,
    offsets: Vec<u32>,
    tags: Vec<(u32, String)>,
    values_start: usize,
}

impl RawFrameInfo {
    /// Sanity check limit for tag count to reject malformed data
    const MAX_TAGS: u32 = 20;

    /// Parse raw frame bytes into structured info.
    /// Returns None if the bytes are too short or malformed.
    fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }

        let magic: [u8; 8] = bytes[0..8].try_into().ok()?;
        let frame_length = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        let msg_start = 12;
        let num_tags = u32::from_le_bytes([
            bytes[msg_start],
            bytes[msg_start + 1],
            bytes[msg_start + 2],
            bytes[msg_start + 3],
        ]);

        if num_tags == 0 || num_tags > Self::MAX_TAGS {
            return None;
        }

        let num_offsets = (num_tags - 1) as usize;
        let offsets_start = msg_start + 4;
        let offsets_end = offsets_start + num_offsets * 4;

        if bytes.len() < offsets_end {
            return None;
        }

        let mut offsets = Vec::with_capacity(num_offsets);
        for i in 0..num_offsets {
            let offset_pos = offsets_start + i * 4;
            let offset = u32::from_le_bytes([
                bytes[offset_pos],
                bytes[offset_pos + 1],
                bytes[offset_pos + 2],
                bytes[offset_pos + 3],
            ]);
            offsets.push(offset);
        }

        let tags_start = offsets_end;
        let tags_end = tags_start + (num_tags as usize) * 4;

        if bytes.len() < tags_end {
            return None;
        }

        let mut tags = Vec::with_capacity(num_tags as usize);
        for i in 0..num_tags as usize {
            let tag_pos = tags_start + i * 4;
            let tag_bytes = [
                bytes[tag_pos],
                bytes[tag_pos + 1],
                bytes[tag_pos + 2],
                bytes[tag_pos + 3],
            ];
            let tag_value = u32::from_be_bytes(tag_bytes);
            let tag_str = String::from_utf8_lossy(&tag_bytes)
                .trim_end_matches('\0')
                .to_string();
            tags.push((tag_value, tag_str));
        }

        Some(Self {
            magic,
            frame_length,
            num_tags,
            offsets,
            tags,
            values_start: tags_end,
        })
    }
}

/// Dump raw frame bytes for protocol debugging.
fn dump_raw_frame(bytes: &[u8], label: &str) {
    let header_len = label.len() + 8; // "=== " (4) + label + " ===" (4)
    let footer = "=".repeat(header_len);

    println!("=== {} ===", label);
    println!("Total bytes: {}", bytes.len());

    let info = match RawFrameInfo::parse(bytes) {
        Some(info) => info,
        None => {
            println!("Error: {} too short or malformed", label);
            println!("{}", footer);
            return;
        }
    };

    let magic_str = String::from_utf8_lossy(&info.magic);
    println!("Frame magic: {:?} ({})", info.magic, magic_str);
    println!("Frame length: {} bytes", info.frame_length);
    println!("Number of tags: {}", info.num_tags);

    println!("Offsets ({}):", info.offsets.len());
    for (i, offset) in info.offsets.iter().enumerate() {
        println!("  [{}]: {}", i, offset);
    }

    println!("Tags ({}):", info.num_tags);
    for (i, (tag_value, tag_str)) in info.tags.iter().enumerate() {
        let tag_result = Tag::try_from(*tag_value);
        match tag_result {
            Ok(tag) => println!("  [{}]: {:?} ({})", i, tag, tag_str),
            Err(_) => println!("  [{}]: UNKNOWN 0x{:08x} ({})", i, tag_value, tag_str),
        }
    }

    println!(
        "Values start at byte: {} (frame offset {})",
        info.values_start,
        info.values_start - 12
    );
    println!("{}", footer);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_raw_frame_draft14_response() {
        let bytes = include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5");
        let info = RawFrameInfo::parse(bytes).expect("should parse");

        assert_eq!(&info.magic, b"ROUGHTIM");
        assert_eq!(info.num_tags, 7);
        assert_eq!(info.offsets.len(), 6);

        // Check expected tags for draft-14: SIG, NONC, TYPE, PATH, SREP, CERT, INDX
        let tag_names: Vec<&str> = info.tags.iter().map(|(_, s)| s.as_str()).collect();
        assert_eq!(
            tag_names,
            vec!["SIG", "NONC", "TYPE", "PATH", "SREP", "CERT", "INDX"]
        );
    }

    #[test]
    fn parse_raw_frame_too_short() {
        let bytes = [0u8; 10]; // Too short
        assert!(RawFrameInfo::parse(&bytes).is_none());
    }

    #[test]
    fn parse_raw_frame_invalid_tag_count() {
        let mut bytes =
            include_bytes!("../../roughenough-protocol/testdata/rfc-response.071039e5").to_vec();
        // Set tag count to 0
        bytes[12] = 0;
        bytes[13] = 0;
        bytes[14] = 0;
        bytes[15] = 0;
        assert!(RawFrameInfo::parse(&bytes).is_none());
    }
}
