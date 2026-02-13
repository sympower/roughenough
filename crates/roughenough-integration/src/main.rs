use std::io::{BufReader, Read};
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use roughenough_client::Client;
use roughenough_client::sequence::MeasurementSequence;
use roughenough_client::validation::ResponseValidator;
use roughenough_common::encoding::try_decode_key;
use roughenough_protocol::protocol_ver::ProtocolVersion;

/// RAII guard that ensures server process is killed when dropped.
/// Prevents zombie processes on early return or panic.
struct ServerGuard {
    process: Child,
}

impl ServerGuard {
    fn new(process: Child) -> Self {
        Self { process }
    }

    /// Check if server is still running and log details if it exited.
    fn check_running(&mut self) -> bool {
        match self.process.try_wait() {
            Ok(Some(status)) => {
                eprintln!("    Server exited unexpectedly with status: {status}");
                if let Some(stderr) = self.process.stderr.take() {
                    let mut stderr_content = String::new();
                    if BufReader::new(stderr)
                        .read_to_string(&mut stderr_content)
                        .is_ok()
                    {
                        eprintln!("    Server stderr: {stderr_content}");
                    }
                }
                false
            }
            Err(e) => {
                eprintln!("    Error checking server status: {e}");
                false
            }
            Ok(None) => true,
        }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// The public key that results from an all-zero seed [0u8; 32]
const TEST_PUBLIC_KEY: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

/// A wrong public key (all zeros) - used to test rejection of unexpected servers
const WRONG_PUBLIC_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Start a server, run a client against it, and ensure the client exits cleanly.
/// This is a live end-to-end integration test to catch bugs missed by unit tests.
fn main() {
    println!("=== Running end-to-end integration tests...\n");

    // Test 1: Single server tests (all protocols)
    for (protocol, name) in [("14", "draft-14"), ("8", "draft-08")] {
        for build_mode in ["debug", "release"] {
            println!("=== [{build_mode}] Single server test ({name})...");

            if !test_single_server_with_protocol(build_mode, protocol) {
                eprintln!("=== [{build_mode}] Single server test ({name}) FAILED");
                std::process::exit(1);
            }

            println!("=== [{build_mode}] Single server test ({name}) PASSED\n");
        }
    }

    // Test 2: Wrong public key rejection (all protocols)
    for build_mode in ["debug", "release"] {
        println!("=== [{build_mode}] Wrong public key rejection test...");

        if !test_wrong_public_key_rejected(build_mode) {
            eprintln!("=== [{build_mode}] Wrong public key rejection test FAILED");
            std::process::exit(1);
        }

        println!("=== [{build_mode}] Wrong public key rejection test PASSED\n");
    }

    // Test 2: Multi-server measurement sequence
    for build_mode in ["debug", "release"] {
        println!("=== [{build_mode}] Multi-server sequence test...");

        if !test_multi_server_sequence(build_mode) {
            eprintln!("=== [{build_mode}] Multi-server sequence test FAILED");
            std::process::exit(1);
        }

        println!("=== [{build_mode}] Multi-server sequence test PASSED\n");
    }

    // Test 3: Draft-08 only servers sequence
    for build_mode in ["debug", "release"] {
        println!("=== [{build_mode}] Draft-08 multi-server sequence test...");

        if !test_draft08_server_sequence(build_mode) {
            eprintln!("=== [{build_mode}] Draft-08 multi-server sequence test FAILED");
            std::process::exit(1);
        }

        println!("=== [{build_mode}] Draft-08 multi-server sequence test PASSED\n");
    }

    // Test 4: Mixed protocol version sequence
    for build_mode in ["debug", "release"] {
        println!("=== [{build_mode}] Mixed protocol sequence test...");

        if !test_mixed_protocol_sequence(build_mode) {
            eprintln!("=== [{build_mode}] Mixed protocol sequence test FAILED");
            std::process::exit(1);
        }

        println!("=== [{build_mode}] Mixed protocol sequence test PASSED\n");
    }

    // Test 5: Causality violation detection
    for build_mode in ["debug", "release"] {
        println!("=== [{build_mode}] Causality violation detection test...");

        if !test_causality_violation_detection(build_mode) {
            eprintln!("=== [{build_mode}] Causality violation detection test FAILED");
            std::process::exit(1);
        }

        println!("=== [{build_mode}] Causality violation detection test PASSED\n");
    }

    println!("=== All end-to-end integration tests PASSED");
}

/// Test that client rejects responses when given the wrong public key (all protocols)
fn test_wrong_public_key_rejected(build_mode: &str) -> bool {
    for protocol in ["14", "8"] {
        if !test_wrong_public_key_rejected_protocol(build_mode, protocol) {
            return false;
        }
    }
    true
}

fn test_wrong_public_key_rejected_protocol(build_mode: &str, protocol: &str) -> bool {
    let server_path = format!("target/{build_mode}/roughenough_server");
    let client_path = format!("target/{build_mode}/roughenough_client");

    let mut server = match start_server(&server_path, 2003, protocol) {
        Some(s) => s,
        None => return false,
    };

    thread::sleep(Duration::from_millis(200));

    if !server.check_running() {
        return false;
    }

    // Run client with WRONG public key - should fail validation
    println!(
        "    Running client with wrong public key (protocol {}, expecting failure)...",
        protocol
    );
    let client_result = Command::new(&client_path)
        .args([
            "127.0.0.1",
            "2003",
            "-n",
            "1",
            "-k",
            WRONG_PUBLIC_KEY,
            "-P",
            protocol,
        ])
        .output();

    // ServerGuard automatically kills process when dropped

    match client_result {
        Ok(output) => {
            if output.status.success() {
                eprintln!(
                    "    ERROR: Client should have failed with wrong public key (protocol {})",
                    protocol
                );
                eprintln!(
                    "    Client stdout: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
                false
            } else {
                println!(
                    "    Client correctly rejected response (protocol {}, exit code: {})",
                    protocol, output.status
                );
                true
            }
        }
        Err(e) => {
            eprintln!("    Failed to run client: {e}");
            false
        }
    }
}

/// Test a single server with specified protocol using the client binary
fn test_single_server_with_protocol(build_mode: &str, protocol: &str) -> bool {
    let server_path = format!("target/{build_mode}/roughenough_server");
    let client_path = format!("target/{build_mode}/roughenough_client");

    // Start the server on default port 2003
    let mut server = match start_server(&server_path, 2003, protocol) {
        Some(s) => s,
        None => return false,
    };

    // Give the server time to start up
    thread::sleep(Duration::from_millis(200));

    // Check if server is still running
    if !server.check_running() {
        return false;
    }

    // Run the client with multiple requests to test multi-batch behavior
    println!(
        "    Running client with 50 requests (protocol {})...",
        protocol
    );
    let client_result = Command::new(client_path)
        .args([
            "127.0.0.1",
            "2003",
            "-n",
            "50",
            "-k",
            TEST_PUBLIC_KEY,
            "-P",
            protocol,
        ])
        .output();

    // ServerGuard automatically kills process when dropped

    // Check client result
    match client_result {
        Ok(output) => {
            if output.status.success() {
                println!("    Client completed successfully");
                true
            } else {
                eprintln!("    Client failed with exit code: {}", output.status);
                eprintln!(
                    "    Client stdout: {}",
                    String::from_utf8_lossy(&output.stdout)
                );
                eprintln!(
                    "    Client stderr: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                false
            }
        }
        Err(e) => {
            eprintln!("    Failed to run client: {e}");
            false
        }
    }
}

/// Test multi-server measurement sequence with 3 servers (all draft-14)
fn test_multi_server_sequence(build_mode: &str) -> bool {
    let server_path = format!("target/{build_mode}/roughenough_server");

    // Start 3 servers on different ports
    let ports = [2001, 2002, 2003];
    let mut servers = Vec::new();

    for port in ports {
        match start_server(&server_path, port, "14") {
            Some(s) => servers.push(s),
            None => return false, // ServerGuards in vec are dropped, killing processes
        }
    }

    // Give servers time to start up
    thread::sleep(Duration::from_millis(300));

    // Check all servers are running
    for (i, server) in servers.iter_mut().enumerate() {
        if !server.check_running() {
            eprintln!("    Server on port {} failed to start", ports[i]);
            return false; // ServerGuards dropped automatically
        }
    }

    println!("    Started {} servers on ports {:?}", servers.len(), ports);

    // Build clients for each server
    run_measurement_sequence(&ports, ProtocolVersion::RfcDraft14, 2)
    // ServerGuards dropped automatically when function returns
}

/// Test multi-server measurement sequence with 3 draft-08 servers
fn test_draft08_server_sequence(build_mode: &str) -> bool {
    let server_path = format!("target/{build_mode}/roughenough_server");

    // Start 3 draft-08 servers on different ports
    let ports = [2001, 2002, 2003];
    let mut servers = Vec::new();

    for port in ports {
        match start_server(&server_path, port, "8") {
            Some(s) => servers.push(s),
            None => return false, // ServerGuards dropped automatically
        }
    }

    // Give servers time to start up
    thread::sleep(Duration::from_millis(300));

    // Check all servers are running
    for (i, server) in servers.iter_mut().enumerate() {
        if !server.check_running() {
            eprintln!("    Server on port {} failed to start", ports[i]);
            return false; // ServerGuards dropped automatically
        }
    }

    println!(
        "    Started {} draft-08 servers on ports {:?}",
        servers.len(),
        ports
    );

    // Build clients for each server with draft-08 protocol
    run_measurement_sequence(&ports, ProtocolVersion::RfcDraft08, 2)
    // ServerGuards dropped automatically when function returns
}

/// Test mixed protocol version sequence (draft-08 and draft-14 servers)
fn test_mixed_protocol_sequence(build_mode: &str) -> bool {
    let server_path = format!("target/{build_mode}/roughenough_server");

    // Start servers with different protocol versions
    // Port 2001: draft-08, Port 2002: draft-14, Port 2003: draft-08
    let configs = [(2001, "8"), (2002, "14"), (2003, "8")];
    let mut servers: Vec<(u16, &str, ServerGuard)> = Vec::new();

    for (port, protocol) in configs {
        match start_server(&server_path, port, protocol) {
            Some(s) => servers.push((port, protocol, s)),
            None => return false, // ServerGuards dropped automatically
        }
    }

    // Give servers time to start up
    thread::sleep(Duration::from_millis(300));

    // Check all servers are running
    for (port, _, server) in servers.iter_mut() {
        if !server.check_running() {
            eprintln!("    Server on port {} failed to start", port);
            return false; // ServerGuards dropped automatically
        }
    }

    println!(
        "    Started {} servers: {:?}",
        servers.len(),
        configs
            .iter()
            .map(|(p, v)| format!("{}(draft-{})", p, v))
            .collect::<Vec<_>>()
    );

    // Build clients with appropriate protocol versions
    run_mixed_protocol_sequence(&configs, 2)
    // ServerGuards dropped automatically when function returns
}

/// Start a server process on the specified port with the given protocol version.
/// Returns a ServerGuard that ensures the process is killed when dropped.
fn start_server(server_path: &str, port: u16, protocol: &str) -> Option<ServerGuard> {
    start_server_with_offset(server_path, port, protocol, 0)
}

/// Start a server process with a time offset (for testing causality violations).
/// Returns a ServerGuard that ensures the process is killed when dropped.
fn start_server_with_offset(
    server_path: &str,
    port: u16,
    protocol: &str,
    time_offset: i16,
) -> Option<ServerGuard> {
    if time_offset == 0 {
        println!(
            "    Starting server on port {} (protocol {})...",
            port, protocol
        );
    } else {
        println!(
            "    Starting server on port {} (protocol {}, offset={}s)...",
            port, protocol, time_offset
        );
    }

    let mut args = vec![
        "-p".to_string(),
        port.to_string(),
        "-P".to_string(),
        protocol.to_string(),
        "-j".to_string(),
        "1".to_string(),
        "-q".to_string(),
    ];

    if time_offset != 0 {
        // Use --fixed-offset=N format to handle negative values correctly
        // (avoids -60 being parsed as a separate flag by clap)
        args.push(format!("--fixed-offset={}", time_offset));
    }

    match Command::new(server_path)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(process) => Some(ServerGuard::new(process)),
        Err(e) => {
            eprintln!("    Failed to start server on port {}: {}", port, e);
            None
        }
    }
}

/// Run a measurement sequence across multiple servers with the same protocol version
fn run_measurement_sequence(ports: &[u16], protocol: ProtocolVersion, rounds: usize) -> bool {
    let public_key = try_decode_key(TEST_PUBLIC_KEY).expect("valid test key");
    let timeout = Duration::from_secs(5);

    let mut clients = Vec::new();
    for port in ports {
        let addr: SocketAddr = format!("127.0.0.1:{}", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let client = Client::builder(addr)
            .hostname(&format!("localhost-{}", port))
            .timeout(timeout)
            .public_key(public_key)
            .protocol_version(protocol)
            .build();

        clients.push(client);
    }

    println!(
        "    Running measurement sequence: {} servers, {} rounds",
        clients.len(),
        rounds
    );

    let mut sequence = MeasurementSequence::new(clients);
    match sequence.run(rounds) {
        Ok(measurements) => {
            println!(
                "    Collected {} measurements across {} servers",
                measurements.len(),
                ports.len()
            );

            // Validate causality
            let violations = ResponseValidator::validate_causality(&measurements);
            if violations.is_empty() {
                println!("    Causality validation passed (no violations)");
                true
            } else {
                eprintln!("    Causality violations detected: {}", violations.len());
                for v in &violations {
                    eprintln!(
                        "      {} (midp={}) vs {} (midp={})",
                        v.measurement_i.hostname(),
                        v.measurement_i.midpoint(),
                        v.measurement_j.hostname(),
                        v.measurement_j.midpoint()
                    );
                }
                false
            }
        }
        Err(e) => {
            eprintln!("    Measurement sequence failed: {e}");
            false
        }
    }
}

/// Test causality violation detection with a server returning intentionally wrong time
fn test_causality_violation_detection(build_mode: &str) -> bool {
    let server_path = format!("target/{build_mode}/roughenough_server");

    // Start 3 servers:
    // - Port 2001: normal time (offset=0)
    // - Port 2002: 60 seconds behind (offset=-60)
    // - Port 2003: normal time (offset=0)
    // The middle server with -60s offset should cause causality violations
    // because its midpoint will be ~60s behind the others.
    let configs = [(2001, "14", 0i16), (2002, "14", -60i16), (2003, "14", 0i16)];
    let mut servers: Vec<(u16, ServerGuard)> = Vec::new();

    for (port, protocol, offset) in configs {
        match start_server_with_offset(&server_path, port, protocol, offset) {
            Some(s) => servers.push((port, s)),
            None => return false, // ServerGuards dropped automatically
        }
    }

    // Give servers time to start up
    thread::sleep(Duration::from_millis(300));

    // Check all servers are running
    for (port, server) in servers.iter_mut() {
        if !server.check_running() {
            eprintln!("    Server on port {} failed to start", port);
            return false; // ServerGuards dropped automatically
        }
    }

    println!(
        "    Started {} servers: {:?}",
        servers.len(),
        configs
            .iter()
            .map(|(p, _, o)| format!("{}(offset={}s)", p, o))
            .collect::<Vec<_>>()
    );

    // Run measurement sequence and expect causality violations
    run_causality_violation_sequence(&configs, 2)
    // ServerGuards dropped automatically when function returns
}

/// Run a measurement sequence expecting causality violations
fn run_causality_violation_sequence(configs: &[(u16, &str, i16)], rounds: usize) -> bool {
    let public_key = try_decode_key(TEST_PUBLIC_KEY).expect("valid test key");
    let timeout = Duration::from_secs(5);

    let mut clients = Vec::new();
    for (port, protocol_str, offset) in configs {
        let addr: SocketAddr = format!("127.0.0.1:{}", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let protocol = match *protocol_str {
            "8" => ProtocolVersion::RfcDraft08,
            _ => ProtocolVersion::RfcDraft14,
        };

        let client = Client::builder(addr)
            .hostname(&format!("localhost-{}(offset={}s)", port, offset))
            .timeout(timeout)
            .public_key(public_key)
            .protocol_version(protocol)
            .build();

        clients.push(client);
    }

    println!(
        "    Running causality violation sequence: {} servers, {} rounds",
        clients.len(),
        rounds
    );

    let mut sequence = MeasurementSequence::new(clients);
    match sequence.run(rounds) {
        Ok(measurements) => {
            println!(
                "    Collected {} measurements across {} servers",
                measurements.len(),
                configs.len()
            );

            // Validate causality - we EXPECT violations due to the time offset
            let violations = ResponseValidator::validate_causality(&measurements);
            if violations.is_empty() {
                eprintln!("    ERROR: Expected causality violations but found none!");
                eprintln!(
                    "    This suggests the time offset server didn't cause detectable violations."
                );
                false
            } else {
                println!(
                    "    Causality violations correctly detected: {} violations",
                    violations.len()
                );
                for v in &violations {
                    println!(
                        "      {} (midp={}) vs {} (midp={})",
                        v.measurement_i.hostname(),
                        v.measurement_i.midpoint(),
                        v.measurement_j.hostname(),
                        v.measurement_j.midpoint()
                    );
                }
                true
            }
        }
        Err(e) => {
            eprintln!("    Measurement sequence failed: {e}");
            false
        }
    }
}

/// Run a measurement sequence across servers with mixed protocol versions
fn run_mixed_protocol_sequence(configs: &[(u16, &str)], rounds: usize) -> bool {
    let public_key = try_decode_key(TEST_PUBLIC_KEY).expect("valid test key");
    let timeout = Duration::from_secs(5);

    let mut clients = Vec::new();
    for (port, protocol_str) in configs {
        let addr: SocketAddr = format!("127.0.0.1:{}", port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();

        let protocol = match *protocol_str {
            "8" => ProtocolVersion::RfcDraft08,
            _ => ProtocolVersion::RfcDraft14,
        };

        let client = Client::builder(addr)
            .hostname(&format!("localhost-{}(draft-{})", port, protocol_str))
            .timeout(timeout)
            .public_key(public_key)
            .protocol_version(protocol)
            .build();

        clients.push(client);
    }

    println!(
        "    Running mixed protocol sequence: {} servers, {} rounds",
        clients.len(),
        rounds
    );

    let mut sequence = MeasurementSequence::new(clients);
    match sequence.run(rounds) {
        Ok(measurements) => {
            println!(
                "    Collected {} measurements across {} servers",
                measurements.len(),
                configs.len()
            );

            // Validate causality
            let violations = ResponseValidator::validate_causality(&measurements);
            if violations.is_empty() {
                println!("    Causality validation passed (no violations)");
                true
            } else {
                eprintln!("    Causality violations detected: {}", violations.len());
                for v in &violations {
                    eprintln!(
                        "      {} (midp={}) vs {} (midp={})",
                        v.measurement_i.hostname(),
                        v.measurement_i.midpoint(),
                        v.measurement_j.hostname(),
                        v.measurement_j.midpoint()
                    );
                }
                false
            }
        }
        Err(e) => {
            eprintln!("    Measurement sequence failed: {e}");
            false
        }
    }
}
