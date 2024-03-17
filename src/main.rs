use clap::{App, Arg};
use goblin::{Hint, peek_bytes};
use goblin::pe::PE;
use scroll::Pread;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
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

fn delete_signature(buf: &[u8], outfile: &Path) -> io::Result<()> {
    let pe = PE::parse(buf).map_err(io_error)?;

    if let Some(optional_header) = pe.header.optional_header {
        if let Some(_load_config_hdr) = optional_header.data_directories.get_load_config_table() {
            let mut modified = buf.to_vec();
            let pe_sig_offset = modified.pread::<u32>(0x3c).map_err(io_error)?;
            let cert_table_offset = pe_sig_offset + if pe.is_64 { 0xa8 } else { 0x98 };

            modified[cert_table_offset as usize..cert_table_offset as usize + 4]
                .copy_from_slice(&(0 as u32).to_le_bytes());

            modified[cert_table_offset as usize + 4..cert_table_offset as usize + 8]
                .copy_from_slice(&(0 as u32).to_le_bytes());

            let mut write_buf = File::create(outfile).map_err(io_error)?;
            write_buf.write_all(&modified).map_err(io_error)?;

            println!("Signature removed successfully.");
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

fn main() {
    let matches = App::new("thief")
        .about("A utility for manipulating digital signatures in PE structure files")
        .arg(
            Arg::with_name("source")
                .help("Source PE structure file (.exe/.dll)")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("pull")
                .long("pull")
                .value_name("output_certificate_file")
                .help("Extract a certificate from any file with a PE structure into .crt")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("sew")
                .long("sew")
                .value_name("input_certificate_file")
                .help("Place the certificate from .crt in any PE structure file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("delete")
                .long("delete")
                .help("Remove certificate from PE structure file"),
        )
        .arg(
            Arg::with_name("replace")
                .long("replace")
                .value_name("target_file")
                .help("Embedding a digital signature from another PE structure file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("impl")
                .long("impl")
                .value_name("target_file")
                .help("Embedding a digital signature from another PE structure file")
                .takes_value(true),
        )
        .get_matches();

    let source_file = matches.value_of("source").unwrap();

    if !is_pe(source_file).unwrap_or(false) {
        println!("Source file is not a PE executable.");
        process::exit(1);
    }

    if matches.is_present("delete") {
        if let Err(e) = delete_signature(&fs::read(source_file).unwrap_or_else(|e| {
            eprintln!("Error reading source file {}: {}", source_file, e);
            process::exit(1);
        }), Path::new(source_file)) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    } else if let Some(output_cert_file) = matches.value_of("pull") {
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

        match fs::write(output_cert_file, sig_data) {
            Ok(_) => println!("Signature extracted to {}", output_cert_file),
            Err(e) => {
                eprintln!("Error writing signature to {}: {}", output_cert_file, e);
                process::exit(1);
            }
        }
    } else if let Some(input_cert_file) = matches.value_of("sew") {
        let signature = match fs::read(input_cert_file) {
            Ok(sig) => sig,
            Err(e) => {
                eprintln!("Error reading input certificate file {}: {}", input_cert_file, e);
                process::exit(1);
            }
        };

        if let Err(e) = implant_signature(&fs::read(source_file).unwrap_or_else(|e| {
            eprintln!("Error reading source file {}: {}", source_file, e);
            process::exit(1);
        }), &signature, Path::new(source_file)) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    } else if let Some(dest_file) = matches.value_of("replace") {
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

        let unsigned_buf = match fs::read(dest_file) {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("Error reading destination file: {}", e);
                process::exit(1);
            }
        };

        if let Err(e) = implant_signature(&unsigned_buf, sig_data, Path::new(dest_file)) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    } else if let Some(dest_file) = matches.value_of("impl") {
        let dest_path = Path::new(dest_file);
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

        if let Err(e) = implant_signature(&fs::read(dest_path).unwrap_or_else(|e| {
            eprintln!("Error reading destination file {}: {}", dest_path.display(), e);
            process::exit(1);
        }), &sig_data, dest_path) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    } else {
        println!("Invalid arguments.");
        process::exit(1);
    }
}
