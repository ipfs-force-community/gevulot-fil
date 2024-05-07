use std::env;
use std::fs::create_dir_all;
use std::fs::rename;
use std::fs::File;
use std::io::copy;
use std::io::stderr;
use std::io::stdout;
use std::io::Read;
use std::io::Stdout;
use std::io::Write;
use std::io::{self};
use std::path::Path;
use std::path::PathBuf;
use std::process::exit;
use std::process::Command;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use dialoguer::theme::ColorfulTheme;
use dialoguer::MultiSelect;
use dialoguer::Select;
use filecoin_proofs::param::get_digest_for_file_within_cache;
use filecoin_proofs::param::get_full_path_for_file_within_cache;
use filecoin_proofs::param::has_extension;
use flate2::read::GzDecoder;
use lazy_static::lazy_static;
use pbr::ProgressBar;
use pbr::Units;
use reqwest::blocking::Client;
use reqwest::header;
use reqwest::Proxy;
use reqwest::Url;
use storage_proofs_core::parameter_cache::parameter_cache_dir;
use storage_proofs_core::parameter_cache::parameter_cache_dir_name;
use storage_proofs_core::parameter_cache::ParameterMap;
use storage_proofs_core::parameter_cache::GROTH_PARAMETER_EXT;
use tar::Archive;

lazy_static! {
    static ref CLI_ABOUT: String = format!(
        "Downloads missing or outdated Groth parameter files from ipfs using ipget.\n\n
        Set the $FIL_PROOFS_PARAMETER_CACHE env-var to specify the path to the parameter cache
        directory (location where params are written), otherwise params will be written to '{}'.",
        parameter_cache_dir_name(),
    );
}

const DEFAULT_JSON: &str = include_str!("../parameters.json");
const DEFAULT_IPGET_VERSION: &str = "v0.10.0";

#[inline]
fn get_ipget_dir(version: &str) -> String {
    format!("/var/tmp/ipget-{}", version)
}

#[inline]
fn get_ipget_path(version: &str) -> String {
    format!("{}/ipget/ipget", get_ipget_dir(version))
}

/// Reader with progress bar.
struct FetchProgress<R> {
    reader: R,
    progress_bar: ProgressBar<Stdout>,
}

impl<R: Read> Read for FetchProgress<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf).map(|n| {
            self.progress_bar.add(n as u64);
            n
        })
    }
}

impl<R: Read> FetchProgress<R> {
    fn new(reader: R, size: u64) -> Self {
        let mut progress_bar = ProgressBar::new(size);
        progress_bar.set_units(Units::Bytes);
        FetchProgress {
            reader,
            progress_bar,
        }
    }
}

/// Download a version of ipget.
fn download_ipget(version: &str, verbose: bool) -> Result<()> {
    println!("downloading ipget");

    let (os, ext) = if cfg!(target_os = "macos") {
        ("darwin", "tar.gz")
    } else if cfg!(target_os = "windows") {
        // TODO: enable Windows by adding support for .zip files.
        // ("windows", "zip")
        unimplemented!("paramfetch does not currently support Windows/.zip downloads");
    } else {
        ("linux", "tar.gz")
    };

    // Request ipget file.
    let url = Url::parse(&format!(
        "https://dist.ipfs.io/ipget/{}/ipget_{}_{}-amd64.{}",
        version, version, os, ext,
    ))?;
    let client = Client::builder()
        .proxy(Proxy::custom(move |url| env_proxy::for_url(url).to_url()))
        .build()?;
    let mut resp = client.get(url).send()?;
    if !resp.status().is_success() {
        eprintln!("non-200 response status:\n{:?}\nexiting", resp);
        exit(1);
    }

    let size: Option<u64> = resp
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|val| val.to_str().unwrap().parse().ok());

    // Write downloaded file.
    let write_path = format!("{}.{}", get_ipget_dir(version), ext);
    let mut writer = File::create(&write_path).expect("failed to create file");
    if verbose {
        if let Some(size) = size {
            let mut resp_with_progress = FetchProgress::new(resp, size);
            copy(&mut resp_with_progress, &mut writer).expect("failed to write download to file");
        }
    } else {
        copy(&mut resp, &mut writer).expect("failed to write download to file");
    }
    drop(writer);

    // Unzip and unarchive downloaded file.
    let reader = File::open(&write_path).expect("failed to open downloaded tar file");
    if ext == "tar.gz" {
        let unzipper = GzDecoder::new(reader);
        let mut unarchiver = Archive::new(unzipper);
        unarchiver
            .unpack(get_ipget_dir(version))
            .expect("failed to unzip and unarchive");
    } else {
        unimplemented!("unzip is not yet supported");
    }
    println!(
        "successfully downloaded ipget binary: {}",
        get_ipget_path(version),
    );

    Ok(())
}

/// Check which files are outdated (or no not exist).
fn get_filenames_requiring_download(
    parameter_map: &ParameterMap,
    selected_filenames: Vec<String>,
    verify: bool,
) -> Vec<String> {
    selected_filenames
        .into_iter()
        .filter(|filename| {
            let path = get_full_path_for_file_within_cache(filename);
            if !path.exists() {
                return true;
            };
            if !verify {
                return false;
            }
            println!("calculating digest for {}", path.display());
            let calculated_digest = match get_digest_for_file_within_cache(filename) {
                Ok(digest) => digest,
                Err(e) => {
                    eprintln!("failed to hash file {}, marking for download", e);
                    return true;
                }
            };
            let expected_digest = &parameter_map[filename].digest;
            if &calculated_digest == expected_digest {
                false
            } else {
                println!("file has unexpected digest, marking for download");
                let new_filename = format!("{}-invalid-digest", filename);
                let new_path = path.with_file_name(new_filename);
                println!("moving invalid params to: {}", new_path.display());
                rename(path, new_path).expect("failed to move file");
                true
            }
        })
        .collect()
}

fn download_file_with_ipget(
    cid: &str,
    path: &Path,
    ipget_path: &Path,
    ipget_args: &Option<String>,
    verbose: bool,
) -> Result<()> {
    // IPFS_GATEWAY=https://proof-parameters.s3.cn-south-1.jdcloud-oss.com/ipfs/
    let url = if let Some(gw) = env::var("IPFS_GATEWAY").ok() {
        format!("{}/{}", gw.trim_end_matches('/'), cid)
    } else {
        cid.to_string()
    };
    let mut args = vec![url, "-o".to_string(), path.display().to_string()];
    if let Some(ipget_args) = ipget_args {
        args.extend(ipget_args.split_whitespace().map(|x| x.to_string()));
    }
    let progress_flag = "--progress".to_string();
    if verbose && !args.contains(&progress_flag) {
        args.push(progress_flag);
    }
    println!(
        "spawning subprocess: {} {}",
        ipget_path.display(),
        args.join(" ")
    );
    let output = Command::new(ipget_path.as_os_str())
        .args(&args)
        .output()
        .with_context(|| "failed to spawn ipget subprocess")?;
    if verbose {
        stdout()
            .write_all(&output.stdout)
            .with_context(|| "failed to write ipget's stdout")?;
        stderr()
            .write_all(&output.stderr)
            .with_context(|| "failed to write ipget's stderr")?;
    }
    ensure!(output.status.success(), "ipget returned non-zero exit code");
    Ok(())
}

#[derive(Debug, Parser)]
#[command(version, about=CLI_ABOUT.as_str())]
struct Cli {
    /// Use a specific JSON file.
    #[arg(short, long, env, value_name = "PATH TO JSON FILE")]
    json: Option<String>,

    /// Prompt to retry file downloads on failure.
    #[arg(short, long, env)]
    retry: bool,

    /// Download parameters for all sector sizes.
    #[arg(short = 'a', long, env, conflicts_with = "sector_sizes")]
    all: bool,

    /// A comma-separated list of sector sizes (in bytes) for which Groth parameters will be downloaded.
    #[arg(
        short = 'z',
        long,
        env,
        value_name = "SECTOR SIZES",
        conflicts_with = "all",
        value_delimiter = ','
    )]
    sector_sizes: Option<Vec<bytesize::ByteSize>>,

    /// Specify whether to verify the proof parameter file
    #[arg(long, env, default_value = "false")]
    verify: bool,

    #[arg(short = 'v', long, env, default_value = "true")]
    verbose: bool,

    /// Path to an ipget binary. If this argument is not given, paramfetch with look \
    /// for ipget in the default location: /var/tmp/ipget-<version>/ipget/ipget. If no binary \
    /// is found in the default location, paramfetch will download ipget into that location.
    #[arg(
        short = 'i',
        long,
        env,
        value_name = "PATH TO IPGET",
        conflicts_with = "ipget_version"
    )]
    ipget_bin: Option<String>,

    /// Set the version of ipget to use.
    #[arg(long, env, value_name = "VERSION", conflicts_with = "ipget_bin")]
    ipget_version: Option<String>,

    /// Specify additional arguments for ipget.
    #[arg(long, value_name = "ARGS")]
    ipget_args: Option<String>,
}

pub fn main() {
    let cli = Cli::parse();

    // Parse parameters.json file.
    let parameter_map: ParameterMap = match cli.json {
        Some(json_path) => {
            let mut json_file = File::open(&json_path)
                .map_err(|e| {
                    eprintln!("failed to open json file, exiting\n{:?}", e);
                    exit(1);
                })
                .unwrap();
            serde_json::from_reader(&mut json_file)
                .map_err(|e| {
                    eprintln!("failed to parse json file, exiting\n{:?}", e);
                    exit(1);
                })
                .unwrap()
        }
        None => serde_json::from_str(DEFAULT_JSON)
            .map_err(|e| {
                eprintln!("failed to parse built-in json, exiting\n{:?}", e);
                exit(1);
            })
            .unwrap(),
    };

    let mut filenames: Vec<String> = parameter_map.keys().cloned().collect();

    // Filter out unwanted sector sizes from params files (.params files only, leave verifying-key
    // files).
    if let Some(ref sector_sizes) = cli.sector_sizes {
        filenames.retain(|filename| {
            let sector_size = bytesize::ByteSize(parameter_map[filename].sector_size);
            let remove = has_extension(filename, GROTH_PARAMETER_EXT)
                && !sector_sizes.contains(&sector_size);
            !remove
        });
    }

    // Determine which files are outdated.
    filenames = get_filenames_requiring_download(&parameter_map, filenames, cli.verify);
    if filenames.is_empty() {
        println!("no outdated files, exiting");
        return;
    }

    // If no sector size CLI argument was provided, prompt the user to select which files to
    // download.
    if cli.sector_sizes.is_none() && !cli.all {
        let filename_strings: Vec<String> = filenames
            .iter()
            .map(|filename| {
                let sector_size = bytesize::ByteSize(parameter_map[filename].sector_size);
                format!("{} ({})", filename, sector_size)
            })
            .collect();
        filenames = MultiSelect::with_theme(&ColorfulTheme::default())
            .with_prompt("Select files to be downloaded (press space key to select)")
            .items(&filename_strings)
            .interact()
            .expect("MultiSelect interaction failed")
            .into_iter()
            .map(|i| filenames[i].clone())
            .collect();
    }

    println!(
        "{} files to be downloaded: {:?}",
        filenames.len(),
        filenames
    );
    if filenames.is_empty() {
        println!("no files to download, exiting");
        return;
    }

    let ipget_path = if let Some(path_str) = cli.ipget_bin {
        let path = PathBuf::from(path_str);
        if !path.exists() {
            eprintln!(
                "provided ipget binary not found: {}, exiting",
                path.display()
            );
            exit(1);
        }

        path
    } else {
        let ipget_version = cli
            .ipget_version
            .unwrap_or_else(|| DEFAULT_IPGET_VERSION.to_string());
        let tmp_path = get_ipget_path(&ipget_version);
        let path = PathBuf::from(&tmp_path);
        if !path.exists() {
            println!("ipget binary not found: {}", path.display());
            download_ipget(&ipget_version, cli.verbose).expect("ipget download failed");
        }

        path
    };
    println!("using ipget binary: {}", ipget_path.display());

    create_dir_all(parameter_cache_dir()).expect("failed to create param cache dir");

    loop {
        for filename in &filenames {
            println!("downloading params file with ipget: {}", filename);
            let path = get_full_path_for_file_within_cache(filename);
            match download_file_with_ipget(
                &parameter_map[filename].cid,
                &path,
                &ipget_path,
                &cli.ipget_args,
                cli.verbose,
            ) {
                Ok(_) => println!("finished downloading params file"),
                Err(e) => eprintln!("failed to download params file: {}", e),
            };
        }
        filenames = get_filenames_requiring_download(&parameter_map, filenames, cli.verify);
        if filenames.is_empty() {
            println!("succesfully updated all files, exiting");
            return;
        }
        eprintln!(
            "{} files failed to be fetched: {:?}",
            filenames.len(),
            filenames
        );
        let retry = cli.retry
            || Select::with_theme(&ColorfulTheme::default())
                .with_prompt("Retry failed downloads? (press arrow keys to select)")
                .items(&["y", "n"])
                .interact()
                .map(|i| i == 0)
                .expect("Select interaction failed");
        if !retry {
            eprintln!("not retrying failed downloads, exiting");
            exit(1);
        }
    }
}
