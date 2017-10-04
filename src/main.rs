#![forbid(exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
unknown_crate_types, warnings)]
#![deny(bad_style, deprecated, improper_ctypes, missing_docs,
non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy))]

#[macro_use]
extern crate log;
extern crate log4rs;
extern crate crypto;
extern crate rand;
extern crate docopt;
extern crate futures;
extern crate maidsafe_utilities;
extern crate rustc_serialize;
extern crate self_encryption;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate unwrap;

use docopt::Docopt;
use futures::{future, Future};
use maidsafe_utilities::serialisation;
use self_encryption::{DataMap, SelfEncryptor, Storage, StorageError};
use std::env;
use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::io::Error as IoError;
use std::path::PathBuf;
use std::string::String;

mod crypt;

#[cfg_attr(rustfmt, rustfmt_skip)]
static USAGE: &'static str = "
Usage: pwdacean -h
       pwdacean -e <target>
       pwdacean -d <destination>

Options:
    -h, --help      Display this message.
    -e, --encrypt   Encrypt a file.
    -d, --decrypt   Decrypt a file.
";

#[derive(RustcDecodable, Debug, Deserialize)]
struct Args {
    arg_target: Option<String>,
    arg_destination: Option<String>,
    flag_encrypt: bool,
    flag_decrypt: bool,
    flag_help: bool,
}

fn main() {
    log4rs::init_file("config/log4rs.yaml", Default::default()).unwrap();

    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());
    if args.flag_help {
        println!("{:?}", args)
    }


//    let message = "Hello World!";
//
//    let mut key: [u8; 32] = [0; 32];
//    let mut iv: [u8; 16] = [0; 16];
//
//    // In a real program, the key and iv may be determined
//    // using some other mechanism. If a password is to be used
//    // as a key, an algorithm like PBKDF2, Bcrypt, or Scrypt (all
//    // supported by Rust-Crypto!) would be a good choice to derive
//    // a password. For the purposes of this example, the key and
//    // iv are just random values.
//    let mut rng = OsRng::new().ok().unwrap();
//    rng.fill_bytes(&mut key);
//    rng.fill_bytes(&mut iv);
//
//    let encrypted_data = crypt::encrypt(message.as_bytes(), &key, &iv).ok().unwrap();
//    let decrypted_data = crypt::decrypt(&encrypted_data[..], &key, &iv).ok().unwrap();
//
//    assert!(message.as_bytes() == &decrypted_data[..]);
//    let res = message.as_bytes() == &decrypted_data[..];
//    info!("encrypting and decrypting worked: {:#?}", res);
//    info!("decrypted message: {}", str::from_utf8(&decrypted_data[..]).unwrap());


    // Testing self_encrypt
    let mut chunk_store_dir = env::temp_dir();
    chunk_store_dir.push("chunk_store_test/");
    let _ = fs::create_dir(chunk_store_dir.clone());
    let mut storage =
        DiskBasedStorage { storage_path: unwrap!(chunk_store_dir.to_str()).to_owned() };

    let mut data_map_file = chunk_store_dir;
    data_map_file.push("data_map");

    if args.flag_encrypt && args.arg_target.is_some() {
        encrypt_file(args.arg_target, storage, data_map_file)
    }

    if args.flag_decrypt && args.arg_destination.is_some() {
        decrypt_file(args.arg_destination, storage, data_map_file)
    }

}

fn to_hex(ch: u8) -> String {
    fmt::format(format_args!("{:02x}", ch))
}

fn file_name(name: &[u8]) -> String {
    let mut string = String::new();
    for ch in name {
        string.push_str(&to_hex(*ch));
    }
    string
}

#[derive(Debug)]
struct DiskBasedStorageError {
    io_error: IoError,
}

impl Display for DiskBasedStorageError {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "I/O error getting/putting: {}", self.io_error)
    }
}

impl StdError for DiskBasedStorageError {
    fn description(&self) -> &str {
        "DiskBasedStorage Error"
    }
}

impl From<IoError> for DiskBasedStorageError {
    fn from(error: IoError) -> DiskBasedStorageError {
        DiskBasedStorageError { io_error: error }
    }
}

impl StorageError for DiskBasedStorageError {}

struct DiskBasedStorage {
    pub storage_path: String,
}

impl DiskBasedStorage {
    fn calculate_path(&self, name: &[u8]) -> PathBuf {
        let mut path = PathBuf::from(self.storage_path.clone());
        path.push(file_name(name));
        path
    }
}

impl Storage for DiskBasedStorage {
    type Error = DiskBasedStorageError;

    fn get(&self, name: &[u8]) -> Box<Future<Item = Vec<u8>, Error = DiskBasedStorageError>> {
        let path = self.calculate_path(name);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) => return Box::new(future::err(From::from(error))),
        };
        let mut data = Vec::new();
        let result = file.read_to_end(&mut data).map(move |_| data).map_err(
            From::from,
        );
        Box::new(future::result(result))
    }

    fn put(
        &mut self,
        name: Vec<u8>,
        data: Vec<u8>,
    ) -> Box<Future<Item = (), Error = DiskBasedStorageError>> {
        let path = self.calculate_path(&name);
        let mut file = match File::create(&path) {
            Ok(file) => file,
            Err(error) => return Box::new(future::err(From::from(error))),
        };

        let result = file.write_all(&data[..])
            .map(|_| {
                println!("Chunk written to {:?}", path);
            })
            .map_err(From::from);
        Box::new(future::result(result))
    }
}

fn encrypt_file(target: Option<String>, storage: DiskBasedStorage, data_map_file: PathBuf) -> () {
    if let Ok(mut file) = File::open(unwrap!(target.clone())) {
        match file.metadata() {
            Ok(metadata) => {
                if metadata.len() > self_encryption::MAX_FILE_SIZE as u64 {
                    return println!(
                        "File size too large {} is greater than 1GB",
                        metadata.len()
                    );
                }
            }
            Err(error) => return println!("{}", error.description().to_string()),
        }

        let mut data = Vec::new();
        match file.read_to_end(&mut data) {
            Ok(_) => (),
            Err(error) => return println!("{}", error.description().to_string()),
        }

        let se = SelfEncryptor::new(storage, DataMap::None).expect(
            "Encryptor construction shouldn't fail.",
        );
        se.write(&data, 0).wait().expect(
            "Writing to encryptor shouldn't fail.",
        );
        let (data_map, old_storage) = se.close().wait().expect(
            "Closing encryptor shouldn't fail.",
        );
        storage = old_storage;

        match File::create(data_map_file.clone()) {
            Ok(mut file) => {
                let encoded = unwrap!(serialisation::serialise(&data_map));
                match file.write_all(&encoded[..]) {
                    Ok(_) => println!("Data map written to {:?}", data_map_file),
                    Err(error) => {
                        println!(
                            "Failed to write data map to {:?} - {:?}",
                            data_map_file,
                            error
                        );
                    }
                }
            }
            Err(error) => {
                println!(
                    "Failed to create data map at {:?} - {:?}",
                    data_map_file,
                    error
                );
            }
        }
    } else {
        println!("Failed to open {}", unwrap!(target.clone()));
    }
}

fn decrypt_file(destination: Option<String>, storage: DiskBasedStorage, data_map_file: PathBuf) -> () {
    if let Ok(mut file) = File::open(data_map_file.clone()) {
        let mut data = Vec::new();
        let _ = unwrap!(file.read_to_end(&mut data));

        if let Ok(data_map) = serialisation::deserialise::<DataMap>(&data) {
            let se = SelfEncryptor::new(storage, data_map).expect(
                "Encryptor construction shouldn't fail.",
            );
            let length = se.len();
            if let Ok(mut file) = File::create(unwrap!(destination.clone())) {
                let content = se.read(0, length).wait().expect(
                    "Reading from encryptor shouldn't fail.",
                );
                match file.write_all(&content[..]) {
                    Err(error) => println!("File write failed - {:?}", error),
                    Ok(_) => {
                        println!(
                            "File decrypted to {:?}",
                            unwrap!(destination.clone())
                        )
                    }
                };
            } else {
                println!("Failed to create {}", unwrap!(destination.clone()));
            }
        } else {
            println!("Failed to parse data map - possible corruption");
        }
    } else {
        println!("Failed to open data map at {:?}", data_map_file);
    }
}
