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

fn usage() {
    println!(
        "Usage: {} <source signature file (.exe/.dll)> [--pull <output certificate file (.crt)>] [--sew <input certificate file (.crt)>] [--delete] [--replace <target PE file (.exe/.dll)>] [--impl <target PE file> (.exe/.dll)]",
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
    
    if !is_pe(source_file).unwrap_or(false) {
        println!("Source file is not a PE executable.");
        process::exit(1);
    }
    
    let mut output_certificate: Option<PathBuf> = None;
    let mut input_certificate: Option<PathBuf> = None;
    let mut destination_file: Option<PathBuf> = None;
    let mut should_delete: bool = false;
    let mut destination_mode: bool = false;

    let mut arg_index = 2;

    while arg_index < args.len() {
        match args[arg_index].as_str() {
            "--impl" => {
                if arg_index + 1 >= args.len() {
                    println!("Missing output destination file argument for --impl option.");
                    usage();
                    process::exit(1);
                }
                destination_file = Some(PathBuf::from(&args[arg_index + 1]));
                destination_mode = true;
                arg_index += 2;
            }
            "--pull" => {
                if arg_index + 1 >= args.len() {
                    println!("Missing output certificate file argument for --pull option.");
                    usage();
                    process::exit(1);
                }
                output_certificate = Some(PathBuf::from(&args[arg_index + 1]));
                arg_index += 2;
            }
            "--sew" => {
                if arg_index + 1 >= args.len() {
                    println!("Missing input certificate file argument for --sew option.");
                    usage();
                    process::exit(1);
                }
                input_certificate = Some(PathBuf::from(&args[arg_index + 1]));
                arg_index += 2;
            }
            "--delete" => {
                should_delete = true;
                arg_index += 1;
            }
            _ => {
                println!("Invalid option: {}", args[arg_index]);
                usage();
                process::exit(1);
            }
        }
    }

    if should_delete {
        if let Err(e) = delete_signature(&fs::read(source_file).unwrap_or_else(|e| {
            eprintln!("Error reading source file {}: {}", source_file, e);
            process::exit(1);
        }), Path::new(source_file)) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    } else if destination_mode {
        let destination_out_file = destination_file.unwrap();

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
    
        let unsigned_buf = match fs::read(&destination_out_file) {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("Error reading destination file: {}", e);
                process::exit(1);
            }
        };
        
        if let Err(e) = implant_signature(&unsigned_buf, sig_data, Path::new(&destination_out_file)) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }

    } else if let Some(output_cert_file) = output_certificate {
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

        if let Err(e) = implant_signature(&fs::read(source_file).unwrap_or_else(|e| {
            eprintln!("Error reading source file {}: {}", source_file, e);
            process::exit(1);
        }), &signature, Path::new(source_file)) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    } else {
        println!("Invalid arguments.");
        usage();
        process::exit(1);
    }
}
