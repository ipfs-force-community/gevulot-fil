use std::env;

use anyhow::Result;
use opendal::layers::AsyncBacktraceLayer;
use opendal::layers::LoggingLayer;
use opendal::layers::MinitraceLayer;
use opendal::layers::RetryLayer;
use opendal::raw::HttpClient;
use opendal::services;
use opendal::BlockingOperator;
use opendal::Builder;
use opendal::Operator;
use serde::Deserialize;
use serde::Serialize;
use tracing::warn;
use url::Url;

#[derive(Debug, Clone)]
pub struct FileStorage {
    fs: BlockingOperator,
    fs_base_url: Url,
}

impl FileStorage {
    pub fn new(fs: BlockingOperator, fs_base_url: Url) -> Self {
        Self { fs, fs_base_url }
    }

    pub fn file_url(&self, filename: &str) -> String {
        let mut u = self.fs_base_url.clone();
        u.path_segments_mut().unwrap().push(filename);
        u.as_str().to_string()
    }

    pub fn read_file(&self, filename: &str) -> anyhow::Result<Vec<u8>> {
        Ok(self.fs.read(filename)?.to_vec())
    }
}

impl std::ops::Deref for FileStorage {
    type Target = BlockingOperator;

    fn deref(&self) -> &Self::Target {
        &self.fs
    }
}

#[allow(dead_code)]
pub static STORAGE_S3_DEFAULT_ENDPOINT: &str = "https://s3.amazonaws.com";

/// Storage params which contains the detailed storage info.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageParams {
    Fs {
        root: String,
    },
    S3 {
        endpoint_url: String,
        region: String,
        bucket: String,
        access_key_id: String,
        secret_access_key: String,
        /// Temporary security token used for authentications
        ///
        /// This recommended to use since users don't need to store their permanent credentials in their
        /// scripts or worksheets.
        ///
        /// refer to [documentations](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html) for details.
        security_token: String,
        root: String,
        /// This flag is used internally to control whether databend load
        /// credentials from environment like env, profile and web token.
        disable_credential_loader: bool,
        /// Enable this flag to send API in virtual host style.
        ///
        /// - Virtual Host Style: `https://bucket.s3.amazonaws.com`
        /// - Path Style: `https://s3.amazonaws.com/bucket`
        enable_virtual_host_style: bool,
        /// The RoleArn that used for AssumeRole.
        role_arn: String,
        /// The ExternalId that used for AssumeRole.
        external_id: String,
    },
}

/// init_operator will init an opendal operator based on storage config.
pub fn init_operator(cfg: &StorageParams) -> Result<Operator> {
    let op = match &cfg {
        StorageParams::Fs { root } => build_operator(init_fs_operator(root.clone())?)?,
        cfg @ StorageParams::S3 { .. } => build_operator(init_s3_operator(cfg)?)?,
        // v => {
        //     return Err(io::Error::new(
        //         io::ErrorKind::InvalidInput,
        //         anyhow!("Unsupported storage type: {:?}", v),
        //     )
        //     .into());
        // }
    };

    Ok(op)
}

pub fn build_operator<B: Builder>(builder: B) -> Result<Operator> {
    let ob = Operator::new(builder)?;

    let op = ob
        // Add retry
        .layer(RetryLayer::new().with_jitter())
        // Add async backtrace
        .layer(AsyncBacktraceLayer)
        // Add logging
        .layer(LoggingLayer::default())
        // Add tracing
        .layer(MinitraceLayer);

    Ok(op.finish())
}

/// init_fs_operator will init a opendal fs operator.
fn init_fs_operator(root: String) -> Result<impl Builder> {
    let mut builder = services::Fs::default();

    let mut path = root;
    if !path.starts_with('/') {
        path = env::current_dir().unwrap().join(path).display().to_string();
    }
    builder.root(&path);

    Ok(builder)
}

/// init_s3_operator will init a opendal s3 operator with input s3 config.
fn init_s3_operator(cfg: &StorageParams) -> Result<impl Builder> {
    let StorageParams::S3 {
        endpoint_url,
        region,
        bucket,
        access_key_id,
        secret_access_key,
        security_token,
        root,
        disable_credential_loader,
        enable_virtual_host_style,
        role_arn,
        external_id,
    } = cfg
    else {
        unreachable!();
    };

    let mut builder = services::S3::default();

    // Endpoint.
    builder.endpoint(endpoint_url);

    // Bucket.
    builder.bucket(bucket);

    // Region
    if !region.is_empty() {
        builder.region(region);
    } else if let Ok(region) = env::var("AWS_REGION") {
        // Try to load region from env if not set.
        builder.region(&region);
    } else {
        // FIXME: we should return error here but keep those logic for compatibility.
        warn!(
            "Region is not specified for S3 storage, we will attempt to load it from profiles. If it is still not found, we will use the default region of `us-east-1`."
        );
        builder.region("us-east-1");
    }

    // Credential.
    builder.access_key_id(access_key_id);
    builder.secret_access_key(secret_access_key);
    builder.security_token(security_token);
    builder.role_arn(role_arn);
    builder.external_id(external_id);

    // It's safe to allow anonymous since opendal will perform the check first.
    builder.allow_anonymous();

    // Root.
    builder.root(root);

    // Disable credential loader
    if *disable_credential_loader {
        builder.disable_config_load();
        builder.disable_ec2_metadata();
    }

    // Enable virtual host style
    if *enable_virtual_host_style {
        builder.enable_virtual_host_style();
    }

    let http_builder = reqwest::ClientBuilder::new();
    builder.http_client(HttpClient::build(http_builder)?);

    Ok(builder)
}
