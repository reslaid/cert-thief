use goblin::{Hint, peek_bytes};
use goblin::pe::{PE, data_directories::DataDirectory};
use scroll::{Pread, Pwrite};
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;

fn extract_signature(buf: &[u8]) -> Option<&[u8]> {
    if let Ok(pe) = PE::parse(buf) {
        if let Some(optional_header) = pe.header.optional_header {
            if let Some(_load_config_hdr) = optional_header.data_directories.get_load_config_table() {
                if let Some(cert_table_hdr) = optional_header.data_directories.get_certificate_table() {
                    let start = cert_table_hdr.virtual_address as usize;
                    let end = (cert_table_hdr.virtual_address + cert_table_hdr.size) as usize;
                    return Some(&buf[start..end]);
                }
            }
        }
    }
    None
}

fn implant_signature(buf: &[u8], sig: &[u8], outfile: &Path) -> io::Result<()> {
    let pe = PE::parse(buf).map_err(io_error)?;

    if let Some(optional_header) = pe.header.optional_header {
        if let Some(_load_config_hdr) = optional_header.data_directories.get_load_config_table() {
            let mut modified = buf.to_vec();
            let pe_sig_offset = modified.pread::<u32>(0x3c).map_err(io_error)?;
            let cert_table_offset = pe_sig_offset + if pe.is_64 { 0xa8 } else { 0x98 };

            modified[cert_table_offset as usize..cert_table_offset as usize + 4]
                .copy_from_slice(&(buf.len() as u32).to_le_bytes());

            modified[cert_table_offset as usize + 4..cert_table_offset as usize + 8]
                .copy_from_slice(&(sig.len() as u32).to_le_bytes());

            let mut write_buf = File::create(outfile).map_err(io_error)?;
            write_buf.write_all(&modified).map_err(io_error)?;
            write_buf.write_all(sig).map_err(io_error)?;

            println!("Operation completed successfully.");
            Ok(())
        } else {
            Err(io_error("Failed to get load config table"))
        }
    } else {
        Err(io_error("Failed to parse PE file"))
    }
}

fn io_error<E>(err: E) -> io::Error
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    io::Error::new(io::ErrorKind::Other, err)
}

fn is_pe(file: &str) -> io::Result<bool> {
    let mut fp = File::open(file)?;
    let mut hint: [u8; 16] = [0; 16];
    fp.read_exact(&mut hint)?;

    match peek_bytes(&hint) {
        Ok(Hint::PE) => Ok(true),
        _ => Ok(false),
    }
}

fn usage() {
    println!(
        "Usage: {} <source signature file (.exe)> <destination file (.exe)> [--pull <output certificate file>] [--sew <input certificate file>]",
        env::args().next().unwrap()
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        usage();
        process::exit(1);
    }

    let source_file = &args[1];
    let destination_file = &args[2];

    if !is_pe(source_file).unwrap_or(false) {
        println!("Source file is not a PE executable.");
        process::exit(1);
    }

    let mut output_certificate: Option<PathBuf> = None;
    let mut input_certificate: Option<PathBuf> = None;

    if args.len() == 5 {
        match args[3].as_str() {
            "--pull" => output_certificate = Some(PathBuf::from(&args[4])),
            "--sew" => input_certificate = Some(PathBuf::from(&args[4])),
            _ => {
                println!("Invalid option: {}", args[3]);
                usage();
                process::exit(1);
            }
        }
    } else if args.len() > 5 {
        println!("Invalid number of arguments.");
        usage();
        process::exit(1);
    }

    if let Some(output_cert_file) = output_certificate {
        let signed_buf = match fs::read(source_file) {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("Error reading source signature file: {}", e);
                process::exit(1);
            }
        };

        let sig_data = match extract_signature(&signed_buf) {
            Some(data) => data,
            None => {
                println!("Input file does not contain an Authenticode signature");
                process::exit(1);
            }
        };

        match fs::write(&output_cert_file, sig_data) {
            Ok(_) => println!("Signature extracted to {}", output_cert_file.to_string_lossy()),
            Err(e) => {
                eprintln!("Error writing signature to {}: {}", output_cert_file.to_string_lossy(), e);
                process::exit(1);
            }
        }
    } else if let Some(input_cert_file) = input_certificate {
        let signature = match fs::read(&input_cert_file) {
            Ok(sig) => sig,
            Err(e) => {
                eprintln!("Error reading input certificate file {}: {}", input_cert_file.to_string_lossy(), e);
                process::exit(1);
            }
        };

        let unsigned_buf = match fs::read(destination_file) {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("Error reading destination file: {}", e);
                process::exit(1);
            }
        };

        if let Err(e) = implant_signature(&unsigned_buf, &signature, Path::new(destination_file)) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    } else {
        println!("Invalid arguments.");
        usage();
        process::exit(1);
    }
}
