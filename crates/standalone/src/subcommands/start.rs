use zeroize::Zeroize;
use std::sync::Arc;
use std::path::Path;
use std::path::PathBuf;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::pki_types::PrivatePkcs8KeyDer;

use crate::StandaloneEnv;
use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use clap::ArgAction::SetTrue;
use clap::{Arg, ArgMatches};
use spacetimedb::config::{CertificateAuthority, ConfigFile};
use spacetimedb::db::{Config, Storage};
use spacetimedb::startup::{self, TracingOptions};
use spacetimedb::worker_metrics;
use spacetimedb_client_api::routes::database::DatabaseRoutes;
use spacetimedb_client_api::routes::router;
use spacetimedb_paths::cli::{PrivKeyPath, PubKeyPath};
use spacetimedb_paths::server::ServerDataDir;

pub use spacetimedb_lib::read_file_limited;
pub use spacetimedb_lib::MAX_CERT_BUNDLE_SIZE;
pub use spacetimedb_lib::MAX_KEY_FILE_SIZE;

pub fn cli() -> clap::Command {
    clap::Command::new("start")
        .about("Starts a standalone SpacetimeDB instance")
        .args_override_self(true)
        .override_usage("spacetime start [OPTIONS]")
        .arg(
            Arg::new("listen_addr")
                .long("listen-addr")
                .short('l')
                .default_value("0.0.0.0:3000")
                .help(
                    "The address and port where SpacetimeDB should listen for connections. \
                     This defaults to to listen on all IP addresses on port 80.",
                ),
        )
        .arg(
            Arg::new("data_dir")
                .long("data-dir")
                .help("The path to the data directory for the database")
                .required(true)
                .value_parser(clap::value_parser!(ServerDataDir)),
        )
        .arg(
            Arg::new("enable_tracy")
                .long("enable-tracy")
                .action(SetTrue)
                .help("Enable Tracy profiling"),
        )
        .arg(
            Arg::new("jwt_key_dir")
                .hide(true)
                .long("jwt-key-dir")
                .help("The directory with id_ecdsa and id_ecdsa.pub")
                .value_parser(clap::value_parser!(spacetimedb_paths::cli::ConfigDir)),
        )
        .arg(
            Arg::new("jwt_pub_key_path")
                .long("jwt-pub-key-path")
                .requires("jwt_priv_key_path")
                .help("The path to the public jwt key for verifying identities")
                .value_parser(clap::value_parser!(PubKeyPath)),
        )
        .arg(
            Arg::new("jwt_priv_key_path")
                .long("jwt-priv-key-path")
                .requires("jwt_pub_key_path")
                .help("The path to the private jwt key for issuing identities")
                .value_parser(clap::value_parser!(PrivKeyPath)),
        )
        .arg(Arg::new("in_memory").long("in-memory").action(SetTrue).help(
            "If specified the database will run entirely in memory. After the process exits all data will be lost.",
        ))
        .arg(
            Arg::new("page_pool_max_size").long("page_pool_max_size").help(
                "The maximum size of the page pool in bytes. Should be a multiple of 64KiB. The default is 8GiB.",
            ),
        )
        .arg(spacetimedb_lib::client_trust_cert())
        .arg(spacetimedb_lib::client_trust_system_root_store())
        .arg(spacetimedb_lib::client_no_trust_system_root_store())
        .arg(
            Arg::new("ssl")
            .long("ssl")
            .alias("tls")
            .alias("https")
            .alias("secure")
            .action(clap::ArgAction::SetTrue)
            .help("enables the standalone server to listen in SSL mode, ie. use https instead of http to connect to it. Aliases --tls, --ssl, --secure, or --https. While in this mode, plaintext connections aren't supported, only SSL/TLS.")
        )
        .arg(
//            spacetimedb_lib::cert()
            clap::Arg::new("server-cert")
            .long("server-cert")
            .alias("cert")
            .alias("server-public-cert")
            .value_name("FILE")
            .action(clap::ArgAction::Set)
            .value_parser(clap::value_parser!(std::path::PathBuf))
            .required(false)
            .requires("ssl")
            .help("--cert server.crt: The server sends this to clients during the TLS handshake. ie. server's certificate(in PEM format), which if it's self-signed then this is the file that you must pass to clients via --cert when talking to the server from a client(or the cli), or if signed by a local CA then pass that CA's cert to your clients instead, in order to can trust this server from a client connection. Otherwise, you don't have to pass anything to clients if this cert was signed by a public CA like Let's Encrypt.")
        )
        .arg(
            Arg::new("server-key")
            .long("server-key")
            .alias("server-private-key")
            .alias("private-key")
            .alias("key")
            .requires("ssl")
            .requires("server-cert")
            .value_name("FILE")
            .action(clap::ArgAction::Set)
            .value_parser(clap::value_parser!(PathBuf))
            .help("--key server.key: The server's private key used to decrypt and sign responses. Used for SSL/TLS connections ie. https"))
    // .after_help("Run `spacetime help start` for more detailed information.")
}


/// Loads certificates from a PEM file.
async fn load_certs(file_path: &Path, expected_num: Option<usize>) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = read_file_limited(file_path, MAX_CERT_BUNDLE_SIZE).await?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::Cursor::new(data))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse certificates from {}: {:?}", file_path.display(), e))?;
    if certs.len() < 1 {
        //Err(anyhow::anyhow!("No certificate(s) found in file {}", file_path.display()))
        eprintln!("WARNING: No certificate(s) found in file {}", file_path.display())
    }
//    } else {
//        Ok(certs)
//    }
    if let Some(expected_num)=expected_num {
        let len=certs.len();
        if len == expected_num {
            return Ok(certs);
        } else {
            return Err(anyhow::anyhow!("{} certificate(s) found in file {}, but expected {} cert(s) exactly!", len, file_path.display(), expected_num));
        }
    } else {
        return Ok(certs);
    }
//    match certs.len() {
//        0 => Err(anyhow::anyhow!("No certificate(s) found in file {}, expected {} cert(s)", file_path.display(), expected_num)),
//        expected_num => Ok(certs),
//        _ => Err(anyhow::anyhow!("Multiple certificates found in file {}; only {} certificate(s) is expected.", file_path.display(), expected_num)),
//    }
}

#[allow(dead_code)] // because it's for compile-time check only.
const fn assert_zeroize<T: zeroize::Zeroize + zeroize::ZeroizeOnDrop>() {}
const _: () = {
    assert_zeroize::<PrivatePkcs8KeyDer<'static>>();
    assert_zeroize::<PrivateKeyDer<'static>>();
    assert_zeroize::<ring::signature::RsaKeyPair>();
    assert_zeroize::<ring::signature::EcdsaKeyPair>();
    assert_zeroize::<ring::signature::Ed25519KeyPair>();
};

/// Loads a private key from a PEM file.
async fn load_private_key(file_path: &Path) -> anyhow::Result<PrivateKeyDer<'static>> {

    let mut data = read_file_limited(file_path, MAX_KEY_FILE_SIZE).await?;
    let result = {
        let mut cursor = std::io::Cursor::new(&data); // Borrow data
        assert_zeroize::<PrivatePkcs8KeyDer<'static>>(); // Fails if Zeroize not implemented
        let mut keys: Vec<PrivatePkcs8KeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(
            &mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse private keys from {}: {:?}", file_path.display(), e))?;
        match keys.len() {
            0 => Err(anyhow::anyhow!("No private key found in file {}", file_path.display())),
            //1 => Ok(PrivateKeyDer::Pkcs8(keys.into_iter().next().unwrap())),
            1 => Ok(PrivateKeyDer::Pkcs8(keys.pop().unwrap())),
            _ => Err(anyhow::anyhow!("Multiple private keys found in file {}; only one private key is expected.", file_path.display())),
        }
    };
    data.zeroize();
    result
}

/// Creates a custom CryptoProvider with specific cipher suites.
fn custom_crypto_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::ring::default_provider;
    use rustls::crypto::ring::cipher_suite;
    use rustls::crypto::ring::kx_group;

    let cipher_suites = vec![
        // TLS 1.3
        // test with: $ openssl s_client -connect 127.0.0.1:3000 -tls1_3
        cipher_suite::TLS13_AES_256_GCM_SHA384,
        cipher_suite::TLS13_AES_128_GCM_SHA256,
        cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        // TLS 1.2
        // these are ignored if builder_with_protocol_versions() below doesn't contain TLS 1.2
        // test with: $ openssl s_client -connect 127.0.0.1:3000 -tls1_2
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    // (KX) groups used in TLS handshakes to negotiate the shared secret between client and server.
    let kx_groups = vec![
        kx_group::X25519,
        /*
           X25519:

           An elliptic curve Diffie-Hellman (ECDH) key exchange algorithm based on Curve25519.
           Known for high security, speed, and resistance to side-channel attacks.
           Commonly used in modern TLS (1.2 and 1.3) due to its efficiency and forward secrecy.
           Preferred by many clients (e.g., browsers) for TLS 1.3 handshakes.
           */
        kx_group::SECP256R1,
        /*
           SECP256R1 (aka NIST P-256):

           An elliptic curve standardized by NIST, using a 256-bit prime field.
           Widely supported across TLS 1.2 and 1.3, especially in enterprise environments.
           Slightly less performant than X25519 but trusted due to long-standing use.
           Common in certificates signed by older CAs or legacy systems.
           */
        kx_group::SECP384R1,
        /*
           SECP384R1 (aka NIST P-384):

           Another NIST elliptic curve, using a 384-bit prime field for higher security.
           Offers stronger cryptographic strength than SECP256R1, at the cost of slower performance.
           Used in TLS 1.2 and 1.3 when higher assurance is needed (e.g., government systems).
           Less common than X25519 or SECP256R1 due to computational overhead.
           */
    ];

    rustls::crypto::CryptoProvider {
        cipher_suites,
        kx_groups,
        ..default_provider()
    }
}

pub async fn exec(args: &ArgMatches) -> anyhow::Result<()> {
    let listen_addr = args.get_one::<String>("listen_addr").unwrap();
    let cert_dir = args.get_one::<spacetimedb_paths::cli::ConfigDir>("jwt_key_dir");
    let certs = Option::zip(
        args.get_one::<PubKeyPath>("jwt_pub_key_path").cloned(),
        args.get_one::<PrivKeyPath>("jwt_priv_key_path").cloned(),
    )
    .map(|(jwt_pub_key_path, jwt_priv_key_path)| CertificateAuthority {
        jwt_pub_key_path,
        jwt_priv_key_path,
    });
    let data_dir = args.get_one::<ServerDataDir>("data_dir").unwrap();
    let enable_tracy = args.get_flag("enable_tracy") || std::env::var_os("SPACETIMEDB_TRACY").is_some();
    let storage = if args.get_flag("in_memory") {
        Storage::Memory
    } else {
        Storage::Disk
    };
    let page_pool_max_size = args
        .get_one::<&str>("page_pool_max_size")
        .map(|size| parse_size::Config::new().with_binary().parse_size(size))
        .transpose()
        .context("unrecognized format in `page_pool_max_size`")?
        .map(|size| size as usize);
    let db_config = Config {
        storage,
        page_pool_max_size,
    };

    //banner();
    let exe_name = std::env::current_exe()?;
    let exe_name = exe_name.file_name().unwrap().to_str().unwrap();
    println!("{} version: {}", exe_name, env!("CARGO_PKG_VERSION"));
    println!("{} path: {}", exe_name, std::env::current_exe()?.display());
    println!("database running in data directory {}", data_dir.display());

    let config_path = data_dir.config_toml();
    let config = match ConfigFile::read(&data_dir.config_toml())? {
        Some(config) => config,
        None => {
            let default_config = include_str!("../../config.toml");
            data_dir.create()?;
            config_path.write(default_config)?;
            toml::from_str(default_config).unwrap()
        }
    };

    startup::StartupOptions {
        tracing: Some(TracingOptions {
            config: config.logs,
            reload_config: cfg!(debug_assertions).then_some(config_path),
            disk_logging: std::env::var_os("SPACETIMEDB_DISABLE_DISK_LOGGING")
                .is_none()
                .then(|| data_dir.logs()),
            edition: "standalone".to_owned(),
            tracy: enable_tracy || std::env::var_os("SPACETIMEDB_TRACY").is_some(),
            flamegraph: std::env::var_os("SPACETIMEDB_FLAMEGRAPH").map(|_| {
                std::env::var_os("SPACETIMEDB_FLAMEGRAPH_PATH")
                    .unwrap_or("/var/log/flamegraph.folded".into())
                    .into()
            }),
        }),
        ..Default::default()
    }
    .configure();

    let certs = certs
        .or(config.certificate_authority)
        .or_else(|| cert_dir.map(CertificateAuthority::in_cli_config_dir))
        .context("cannot omit --jwt-{pub,priv}-key-path when those options are not specified in config.toml")?;

    let data_dir = Arc::new(data_dir.clone());
    let ctx = StandaloneEnv::init(db_config, &certs, data_dir).await?;
    worker_metrics::spawn_jemalloc_stats(listen_addr.clone());
    worker_metrics::spawn_tokio_stats(listen_addr.clone());
    worker_metrics::spawn_page_pool_stats(listen_addr.clone(), ctx.page_pool().clone());

    let mut db_routes = DatabaseRoutes::default();
    db_routes.root_post = db_routes.root_post.layer(DefaultBodyLimit::disable());
    db_routes.db_put = db_routes.db_put.layer(DefaultBodyLimit::disable());
    let extra = axum::Router::new().nest("/health", spacetimedb_client_api::routes::health::router());
    let service = router(&ctx, db_routes, extra).with_state(ctx);

    use std::net::SocketAddr;
    let addr: SocketAddr = listen_addr.parse()?;

    if args.get_flag("ssl") {
        // Install custom CryptoProvider at the start
        rustls::crypto::CryptoProvider::install_default(custom_crypto_provider())
            .map_err(|e| anyhow::anyhow!("Failed to install custom CryptoProvider: {:?}", e))?;

        let cert_path: &Path = args.get_one::<PathBuf>("server-cert").context("Missing --cert for SSL")?.as_path();
        let key_path: &Path = args.get_one::<PathBuf>("server-key").context("Missing --key for SSL")?.as_path();

        // Load certificate and private key with file size limit
        let cert_chain = load_certs(cert_path,Some(1)).await?;
        let private_key = load_private_key(key_path).await?;
        //scopeguard::defer! { private_key.zeroize(); }//can't it's moving it
        {
            let mut _cloned_pk=private_key.clone_key();
        }
//        scopeguard::defer! {
//            eprintln!("!!! in defer!");
//            cloned_pk.zeroize();
//            eprintln!("!!! at end of defer!");
//        }//can't it's moving it
//        struct LoggedKey(PrivateKeyDer<'static>);
//        impl Drop for LoggedKey {
//            fn drop(&mut self) {
//                eprintln!("Dropping PrivateKeyDer");
//                self.0.zeroize(); // Explicitly zero for clarity
//            }
//        }
//        {
//            let _foo=LoggedKey(private_key.clone_key());
//        } // well yeah the wrapper gets dropped, obviously.

        // XXX: No revocation status is checked, so a valid-but-revoked cert would pass. (because
        // code doesn't use .with_crls() )

        // Initialize root store
        let mut roots = rustls::RootCertStore::empty();

        // Handle system root certificates
        let trust_system = args.get_flag("client-trust-system-root-store");

        use x509_parser::prelude::FromDer;
        use sha2::{Digest, Sha256};
        //use openssl::sha::{Sha256, Digest};

        if trust_system {
            eprintln!("Was asked to trust the system root store for verifying client certs.");
            //unusual to trust system store with mTLS
            //load system trust store certs
            let cr:rustls_native_certs::CertificateResult = rustls_native_certs::load_native_certs();
            if cr.errors.len() > 0 {
                return Err(anyhow::anyhow!("Failed to load system certs: {:#?}", cr.errors));
            }
            let system_store = cr.expect("impossible now: failed to load system certs.");
            for cert in system_store {
                // Parse and log cert details
                if let Ok((_, parsed)) = x509_parser::prelude::X509Certificate::from_der(cert.as_ref()) {
                    let subject = parsed.subject().to_string();
                    let issuer = parsed.issuer().to_string();
                    let not_after = parsed.validity().not_after.to_string();
                    let serial = parsed.serial.to_string();
                    let fingerprint = format!("{:x}", Sha256::digest(cert.as_ref()));
                    log::info!(
                        "System cert: subject={}, issuer={}, serial={}, expires={}, fingerprint={}",
                        subject, issuer, serial, not_after, fingerprint
                    );
                } else {
                    log::warn!("Failed to parse system cert");
                }

                roots.add(cert)?;
            }
        } else {
            eprintln!("Was asked to not trust the system root store for verifying client certs.");
        }

        // Load custom client trust certificates
        if let Some(client_trust_path) = args.get_one::<PathBuf>("client-trust-cert") {
            let client_certs = load_certs(client_trust_path, None).await?;
            for cert in client_certs {
                // Parse and log cert details
                if let Ok((_, parsed)) = x509_parser::prelude::X509Certificate::from_der(cert.as_ref()) {
                    let subject = parsed.subject().to_string();
                    let issuer = parsed.issuer().to_string();
                    let not_after = parsed.validity().not_after.to_string();
                    let serial = parsed.serial.to_string();
                    let fingerprint = format!("{:x}", Sha256::digest(cert.as_ref()));
                    log::info!(
                        "Trusting client cert/CA (for mTLS): subject={}, issuer={}, serial={}, expires={}, fingerprint={}",
                        subject, issuer, serial, not_after, fingerprint
                    );
                } else {
                    log::warn!("Failed to parse custom cert from file {}", client_trust_path.display());
                }
                roots.add(cert)?;
            }
        }

        // Configure client authentication (mTLS)
        // FIXME: check if this 'danger' thing is as good as using
        // crate::ConfigBuilder::with_client_auth_cert and .with_no_client_auth
        let client_auth: Arc<dyn rustls::server::danger::ClientCertVerifier> = if args.get_one::<PathBuf>("client-trust-cert").is_some() {
            eprintln!("Using mTLS");
            // these roots here may just be the cert we specified without system root store's certs
            rustls::server::WebPkiClientVerifier::builder(roots.into()) //Arc::new(roots))
                .build()
                .map_err(|e| anyhow::anyhow!("Failed to build client verifier: {}", e))?
        } else {
            eprintln!("Not using mTLS.");
            rustls::server::WebPkiClientVerifier::no_client_auth()
        };

        // Create ServerConfig with secure settings
        /*  zeroize: in rustls:
            PR #1492 adds zeroization for session secrets and TLS keys, improving security for non-key material.
            Private keys are still passed to ring, which doesn’t zeroize, so the risk remains for your use case.
           ring:
            No zeroization for RsaKeyPair, EcdsaKeyPair, pkcs8::Document, or Seed
            Relies on the global allocator, which doesn’t guarantee memory zeroing.
            Patching ring to add Zeroize is necessary for private key sanitization.
        */
        let config=
            rustls::ServerConfig::builder_with_protocol_versions(&[
                &rustls::version::TLS13,
//                &rustls::version::TLS12,
            ])
//            rustls::ServerConfig::builder() // using this instead, wouldn't restrict proto versions.
            .with_client_cert_verifier(client_auth)
            //.with_no_client_auth() ^
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| anyhow::anyhow!("Failed to set certificates from files pub:'{}', priv:'{}', err: {}", cert_path.display(), key_path.display(), e))?;

        // Use axum_server with custom config
        // zeroize: Safe, as it only holds an Arc<rustls::ServerConfig> and delegates to rustls for key handling.
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config));

        log::info!(
            "Starting SpacetimeDB with TLSv1.3(only) on {}.",
            addr,
        );
//        axum_server::bind_rustls(addr, tls_config)
//            .serve(service.into_make_service())
//            .await?;
        // Run server in a task
        let server = tokio::spawn(axum_server::bind_rustls(addr, tls_config).serve(service.into_make_service()));
        // Wait for Ctrl+C
        tokio::signal::ctrl_c().await?;
        server.abort(); // Stop the server
        //sanitize_private_key(&mut private_key); // Sanitize the key
        //private_key.zeroize();//not needed(&can't do due to moved, above!) because rustls-pki-types crate implements (on drop) zeroize::Zeroize
        eprintln!("\n!!! server's done.");
    } else {
        log::debug!("Starting SpacetimeDB without any ssl (so it's plaintext) listening on {}", addr);
        axum_server::bind(addr)
            .serve(service.into_make_service())
            .await?;
    }

    Ok(())
}

