#![feature(lazy_cell, duration_constructors)]

use std::fmt;
use std::fs;
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use filestorage::FileStorage;
use gevulot::local::GevulotLocalExecutor;
use gevulot::rpc::GevulotRpcExecutor;
use gevulot::Either;
use gevulot_fil::codec::decode_from;
use gevulot_fil::C2Input;
use gevulot_fil::SecretKey;
use gevulot_fil::WindowPoStPhase2Input;
use gevulot_node::rpc_client::RpcClient;
use gevulot_node::types::Hash;
use panic_hook::install_panic_hook;
use processor::c2::C2Processor;
use processor::windowpost::WindowPoStProcessor;
use tokio::runtime::Builder;
use tracing::info;
use url::Url;
use vc_processors::core::ext::run_consumer;
use vc_processors::core::ext::run_consumer_with_proc;
use vc_processors::core::DaemonProcessor;
use warp::Filter;
use zeroize::Zeroizing;

mod filestorage;
mod gevulot;
mod logging;
mod panic_hook;
mod processor;
mod util;
mod version;

const DEFAULT_FILE_SERVER_LISTEN: &'static str = "127.0.0.1:31313";
const DEFAULT_FILE_SERVER_URL: &'static str = "http://127.0.0.1:31313/static";

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(about, long_about, version = &**version::VERSION)]
struct Cli {
    /// RPC url of the Gevulot node
    #[arg(short, long, env, default_value = "http://localhost:9944")]
    rpc_url: String,
    /// Mock mode
    #[arg(long, default_value = "false")]
    mock: bool,
    /// Private key file path to sign Tx.
    #[clap(
        short,
        long,
        env,
        default_value = "localkey.pki",
        value_name = "KEY FILE PATH"
    )]
    keyfile: PathBuf,

    #[arg(long, env)]
    fileserver_path: PathBuf,
    #[arg(long, env, default_value = DEFAULT_FILE_SERVER_URL)]
    fileserver_base_url: Url,

    #[command(subcommand)]
    commands: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(subcommand)]
    Processor(ProcessorCommands),
    Fileserver {
        /// Listen on the given IP:port
        #[arg(short, long, env, default_value = DEFAULT_FILE_SERVER_LISTEN)]
        listen: SocketAddr,
    },
    #[command(subcommand)]
    Exec(ExecCommands),
}

#[derive(Subcommand)]
enum ProcessorCommands {
    #[command(name = "c2", about = "gevulot c2 processor")]
    C2 {
        #[arg(long, env, value_parser=parse_hash)]
        prover_program: Hash,
        #[arg(long, env, value_parser=parse_hash)]
        verifier_program: Hash,
    },
    #[command(name = "window_post", about = "gevulot windowPoST processor")]
    WindowPoST {
        #[arg(long, env, value_parser=parse_hash)]
        prover_program: Hash,
        #[arg(long, env, value_parser=parse_hash)]
        verifier_program: Hash,
    },
}

#[derive(Subcommand)]
enum ExecCommands {
    #[command(name = "c2", about = "manually execute c2 on gevulot network")]
    C2 {
        #[arg(long, env, value_parser=parse_hash)]
        prover_program: Hash,
        #[arg(long, env, value_parser=parse_hash)]
        verifier_program: Hash,
        #[arg(long, env)]
        input_file: PathBuf,
    },
    #[command(
        name = "window_post",
        about = "manually execute windowPoST on gevulot network"
    )]
    WindowPoST {
        #[arg(long, env, value_parser=parse_hash)]
        prover_program: Hash,
        #[arg(long, env, value_parser=parse_hash)]
        verifier_program: Hash,
        #[arg(long, env)]
        input_file: PathBuf,
    },
}

pub fn main() -> Result<()> {
    logging::init();
    install_panic_hook(true);

    let cli = Cli::parse();

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create runtime");
    let _guard = runtime.enter();

    match cli.commands {
        Commands::Processor(ProcessorCommands::C2 {
            prover_program,
            verifier_program,
        }) => {
            let fs = create_fs(&cli)?;
            let exec = create_gevulot_executor(&cli, fs.clone())?;

            let proc = C2Processor::new(exec, prover_program, verifier_program, fs);
            run_consumer_with_proc(proc)
        }
        Commands::Processor(ProcessorCommands::WindowPoST {
            prover_program,
            verifier_program,
        }) => {
            let fs: FileStorage = create_fs(&cli)?;
            let exec = create_gevulot_executor(&cli, fs.clone())?;

            let proc = WindowPoStProcessor::new(exec, prover_program, verifier_program, fs);
            run_consumer_with_proc(proc)
        }
        Commands::Fileserver { listen } => {
            let routes = warp::path("static")
                .and(warp::fs::dir(cli.fileserver_path.clone()))
                .with(warp::log::custom(|info| {
                    tracing::info!(
                        target: "fileserver",
                        "{} \"{} {} {:?}\" {} \"{}\" \"{}\" {:?}",
                        OptFmt(info.remote_addr()),
                        info.method(),
                        info.path(),
                        info.version(),
                        info.status().as_u16(),
                        OptFmt(info.referer()),
                        OptFmt(info.user_agent()),
                        info.elapsed(),
                    );
                }));

            let jh = runtime.spawn(warp::serve(routes).bind(listen));
            info!(
                "fileserver listen on {}; serve directory: {}",
                listen,
                cli.fileserver_path.display()
            );
            run_consumer::<_, DaemonProcessor>()?;
            runtime.block_on(jh)?;
            Ok(())
        }
        Commands::Exec(ExecCommands::C2 {
            prover_program,
            verifier_program,
            ref input_file,
        }) => {
            let fs = create_fs(&cli)?;
            let exec = create_gevulot_executor(&cli, fs.clone())?;
            let proc = C2Processor::new(exec, prover_program, verifier_program, fs);
            let f = File::open(&input_file).context("open the c2 input file")?;
            let c2_in: C2Input = decode_from(f).context("decode the c2 input data")?;
            let proof = proc.exec(c2_in)?;
            println!("{}", hex::encode(proof));
            Ok(())
        }

        Commands::Exec(ExecCommands::WindowPoST {
            prover_program,
            verifier_program,
            ref input_file,
        }) => {
            let fs: FileStorage = create_fs(&cli)?;
            let exec = create_gevulot_executor(&cli, fs.clone())?;

            let proc = WindowPoStProcessor::new(exec, prover_program, verifier_program, fs);
            let f = File::open(&input_file).context("open the c2 input file")?;
            let wdp2_in: WindowPoStPhase2Input =
                decode_from(f).context("decode the c2 input data")?;
            let proofs = proc.exec_wdp2(wdp2_in)?;
            println!("{}", hex::encode(&proofs[0].1));
            Ok(())
        }
    }
}

fn create_fs(cli: &Cli) -> Result<FileStorage> {
    let fs_path = cli.fileserver_path.display().to_string();
    let fs_op = filestorage::init_operator(&filestorage::StorageParams::Fs { root: fs_path })
        .context("init operator")?;
    Ok(FileStorage::new(
        fs_op.blocking(),
        cli.fileserver_base_url.clone(),
    ))
}

fn create_gevulot_executor(
    cli: &Cli,
    fs: FileStorage,
) -> Result<Either<GevulotRpcExecutor, GevulotLocalExecutor>> {
    Ok(if cli.mock {
        Either::Right(GevulotLocalExecutor::new(fs))
    } else {
        let rpc_client = Arc::new(RpcClient::new(&cli.rpc_url));
        let key_array = fs::read(&cli.keyfile)
            .with_context(|| format!("read key file: {}", cli.keyfile.display()))?;
        let sk = Zeroizing::new(SecretKey::parse_slice(&key_array).context("parse secret key")?);
        Either::Left(GevulotRpcExecutor::new(rpc_client, sk, fs))
    })
}

fn parse_hash(data: &str) -> Result<Hash> {
    Ok(Hash::new(
        hex::decode(data)
            .ok()
            .and_then(|x| x.try_into().ok())
            .context("invalid hash")?,
    ))
}

struct OptFmt<T>(Option<T>);

impl<T: fmt::Display> fmt::Display for OptFmt<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref t) = self.0 {
            fmt::Display::fmt(t, f)
        } else {
            f.write_str("-")
        }
    }
}
