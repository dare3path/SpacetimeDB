use crate::db::raw_def::v9::RawModuleDefV9Builder;
use crate::db::raw_def::RawTableDefV8;
use anyhow::Context;
use sats::typespace::TypespaceBuilder;
use spacetimedb_sats::{impl_serialize, WithTypespace};
use std::any::TypeId;
use std::collections::{btree_map, BTreeMap};

pub const TRACE_DROP_AND_ZEROIZE: bool = false;//TODO: make this depend on ring||pki-types' trace_drop_and_zeroize feature

macro_rules! non_wasm {
    ($($item:item)*) => {
        $(
            #[cfg(not(target_arch = "wasm32"))]
            $item
        )*
    };
}

//XXX: we avoid anything 'mio' or 'openssl' which will fail to compile in wasm32; this this lib is
//used on both wasm32 during 'spacetime publish' compilation and non-wasm32 ie. x86_64
//#[cfg(not(target_arch = "wasm32"))]
non_wasm! {
use tokio::io::AsyncReadExt;
use zeroize::Zeroize; // adds .zeroize to Vec<u8> amongst others.
}

pub mod connection_id;
pub mod db;
mod direct_index_key;
pub mod error;
mod filterable_value;
pub mod identity;
pub mod metrics;
pub mod operator;
pub mod query;
pub mod relation;
pub mod scheduler;
pub mod st_var;
pub mod version;

pub mod type_def {
    pub use spacetimedb_sats::{AlgebraicType, ProductType, ProductTypeElement, SumType};
}
pub mod type_value {
    pub use spacetimedb_sats::{AlgebraicValue, ProductValue};
}

pub use connection_id::ConnectionId;
pub use direct_index_key::{assert_column_type_valid_for_direct_index, DirectIndexKey};
#[doc(hidden)]
pub use filterable_value::Private;
pub use filterable_value::{FilterableValue, IndexScanRangeBoundsTerminator, TermBound};
pub use identity::Identity;
pub use scheduler::ScheduleAt;
pub use spacetimedb_sats::hash::{self, hash_bytes, Hash};
pub use spacetimedb_sats::time_duration::TimeDuration;
pub use spacetimedb_sats::timestamp::Timestamp;
pub use spacetimedb_sats::SpacetimeType;
pub use spacetimedb_sats::__make_register_reftype;
pub use spacetimedb_sats::{self as sats, bsatn, buffer, de, ser};
pub use spacetimedb_sats::{AlgebraicType, ProductType, ProductTypeElement, SumType};
pub use spacetimedb_sats::{AlgebraicValue, ProductValue};

pub const MODULE_ABI_MAJOR_VERSION: u16 = 10;

// if it ends up we need more fields in the future, we can split one of them in two
#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug)]
pub struct VersionTuple {
    /// Breaking change; different major versions are not at all compatible with each other.
    pub major: u16,
    /// Non-breaking change; a host can run a module that requests an older minor version than the
    /// host implements, but not the other way around
    pub minor: u16,
}

impl VersionTuple {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    #[inline]
    pub const fn eq(self, other: Self) -> bool {
        self.major == other.major && self.minor == other.minor
    }

    /// Checks if a host implementing this version can run a module that expects `module_version`
    #[inline]
    pub const fn supports(self, module_version: VersionTuple) -> bool {
        self.major == module_version.major && self.minor >= module_version.minor
    }

    #[inline]
    pub const fn from_u32(v: u32) -> Self {
        let major = (v >> 16) as u16;
        let minor = (v & 0xFF) as u16;
        Self { major, minor }
    }

    #[inline]
    pub const fn to_u32(self) -> u32 {
        (self.major as u32) << 16 | self.minor as u32
    }
}

impl std::fmt::Display for VersionTuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { major, minor } = *self;
        write!(f, "{major}.{minor}")
    }
}

extern crate self as spacetimedb_lib;

//WARNING: Change this structure(or any of their members) is an ABI change.
#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord, SpacetimeType)]
#[sats(crate = crate)]
pub struct TableDesc {
    pub schema: RawTableDefV8,
    /// data should always point to a ProductType in the typespace
    pub data: sats::AlgebraicTypeRef,
}

impl TableDesc {
    pub fn into_table_def(table: WithTypespace<'_, TableDesc>) -> anyhow::Result<RawTableDefV8> {
        let schema = table
            .map(|t| &t.data)
            .resolve_refs()
            .context("recursive types not yet supported")?;
        let schema = schema.into_product().ok().context("table not a product type?")?;
        let table = table.ty();
        anyhow::ensure!(
            table.schema.columns.len() == schema.elements.len(),
            "mismatched number of columns"
        );

        Ok(table.schema.clone())
    }
}

#[derive(Debug, Clone, SpacetimeType)]
#[sats(crate = crate)]
pub struct ReducerDef {
    pub name: Box<str>,
    pub args: Vec<ProductTypeElement>,
}

impl ReducerDef {
    pub fn encode(&self, writer: &mut impl buffer::BufWriter) {
        bsatn::to_writer(writer, self).unwrap()
    }

    pub fn serialize_args<'a>(ty: sats::WithTypespace<'a, Self>, value: &'a ProductValue) -> impl ser::Serialize + 'a {
        ReducerArgsWithSchema { value, ty }
    }

    pub fn deserialize(
        ty: sats::WithTypespace<'_, Self>,
    ) -> impl for<'de> de::DeserializeSeed<'de, Output = ProductValue> + '_ {
        ReducerDeserialize(ty)
    }
}

struct ReducerDeserialize<'a>(sats::WithTypespace<'a, ReducerDef>);

impl<'de> de::DeserializeSeed<'de> for ReducerDeserialize<'_> {
    type Output = ProductValue;

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<Self::Output, D::Error> {
        deserializer.deserialize_product(self)
    }
}

impl<'de> de::ProductVisitor<'de> for ReducerDeserialize<'_> {
    type Output = ProductValue;

    fn product_name(&self) -> Option<&str> {
        Some(&self.0.ty().name)
    }
    fn product_len(&self) -> usize {
        self.0.ty().args.len()
    }
    fn product_kind(&self) -> de::ProductKind {
        de::ProductKind::ReducerArgs
    }

    fn visit_seq_product<A: de::SeqProductAccess<'de>>(self, tup: A) -> Result<Self::Output, A::Error> {
        de::visit_seq_product(self.0.map(|r| &*r.args), &self, tup)
    }

    fn visit_named_product<A: de::NamedProductAccess<'de>>(self, tup: A) -> Result<Self::Output, A::Error> {
        de::visit_named_product(self.0.map(|r| &*r.args), &self, tup)
    }
}

struct ReducerArgsWithSchema<'a> {
    value: &'a ProductValue,
    ty: sats::WithTypespace<'a, ReducerDef>,
}
impl_serialize!([] ReducerArgsWithSchema<'_>, (self, ser) => {
    use itertools::Itertools;
    use ser::SerializeSeqProduct;
    let mut seq = ser.serialize_seq_product(self.value.elements.len())?;
    for (value, elem) in self.value.elements.iter().zip_eq(&self.ty.ty().args) {
        seq.serialize_element(&self.ty.with(&elem.algebraic_type).with_value(value))?;
    }
    seq.end()
});

//WARNING: Change this structure (or any of their members) is an ABI change.
#[derive(Debug, Clone, Default, SpacetimeType)]
#[sats(crate = crate)]
pub struct RawModuleDefV8 {
    pub typespace: sats::Typespace,
    pub tables: Vec<TableDesc>,
    pub reducers: Vec<ReducerDef>,
    pub misc_exports: Vec<MiscModuleExport>,
}

impl RawModuleDefV8 {
    pub fn builder() -> ModuleDefBuilder {
        ModuleDefBuilder::default()
    }

    pub fn with_builder(f: impl FnOnce(&mut ModuleDefBuilder)) -> Self {
        let mut builder = Self::builder();
        f(&mut builder);
        builder.finish()
    }
}

/// A versioned raw module definition.
///
/// This is what is actually returned by the module when `__describe_module__` is called, serialized to BSATN.
#[derive(Debug, Clone, SpacetimeType)]
#[sats(crate = crate)]
#[non_exhaustive]
pub enum RawModuleDef {
    V8BackCompat(RawModuleDefV8),
    V9(db::raw_def::v9::RawModuleDefV9),
    // TODO(jgilles): It would be nice to have a custom error message if this fails with an unknown variant,
    // but I'm not sure if that can be done via the Deserialize trait.
}

/// A builder for a [`RawModuleDefV8`].
/// Deprecated.
#[derive(Default)]
pub struct ModuleDefBuilder {
    /// The module definition.
    module: RawModuleDefV8,
    /// The type map from `T: 'static` Rust types to sats types.
    type_map: BTreeMap<TypeId, sats::AlgebraicTypeRef>,
}

impl ModuleDefBuilder {
    pub fn add_type<T: SpacetimeType>(&mut self) -> AlgebraicType {
        TypespaceBuilder::add_type::<T>(self)
    }

    /// Add a type that may not correspond to a Rust type.
    /// Used only in tests.
    #[cfg(feature = "test")]
    pub fn add_type_for_tests(&mut self, name: &str, ty: AlgebraicType) -> spacetimedb_sats::AlgebraicTypeRef {
        let slot_ref = self.module.typespace.add(ty);
        self.module.misc_exports.push(MiscModuleExport::TypeAlias(TypeAlias {
            name: name.to_owned(),
            ty: slot_ref,
        }));
        slot_ref
    }

    /// Add a table that may not correspond to a Rust type.
    /// Wraps it in a `TableDesc` and generates a corresponding `ProductType` in the typespace.
    /// Used only in tests.
    /// Returns the `AlgebraicTypeRef` of the generated `ProductType`.
    #[cfg(feature = "test")]
    pub fn add_table_for_tests(&mut self, schema: RawTableDefV8) -> spacetimedb_sats::AlgebraicTypeRef {
        let ty: ProductType = schema
            .columns
            .iter()
            .map(|c| ProductTypeElement {
                name: Some(c.col_name.clone()),
                algebraic_type: c.col_type.clone(),
            })
            .collect();
        let data = self.module.typespace.add(ty.into());
        self.add_type_alias(TypeAlias {
            name: schema.table_name.clone().into(),
            ty: data,
        });
        self.add_table(TableDesc { schema, data });
        data
    }

    pub fn add_table(&mut self, table: TableDesc) {
        self.module.tables.push(table)
    }

    pub fn add_reducer(&mut self, reducer: ReducerDef) {
        self.module.reducers.push(reducer)
    }

    #[cfg(feature = "test")]
    pub fn add_reducer_for_tests(&mut self, name: impl Into<Box<str>>, args: ProductType) {
        self.add_reducer(ReducerDef {
            name: name.into(),
            args: args.elements.to_vec(),
        });
    }

    pub fn add_misc_export(&mut self, misc_export: MiscModuleExport) {
        self.module.misc_exports.push(misc_export)
    }

    pub fn add_type_alias(&mut self, type_alias: TypeAlias) {
        self.add_misc_export(MiscModuleExport::TypeAlias(type_alias))
    }

    pub fn typespace(&self) -> &sats::Typespace {
        &self.module.typespace
    }

    pub fn finish(self) -> RawModuleDefV8 {
        self.module
    }
}

impl TypespaceBuilder for ModuleDefBuilder {
    fn add(
        &mut self,
        typeid: TypeId,
        name: Option<&'static str>,
        make_ty: impl FnOnce(&mut Self) -> AlgebraicType,
    ) -> AlgebraicType {
        let r = match self.type_map.entry(typeid) {
            btree_map::Entry::Occupied(o) => *o.get(),
            btree_map::Entry::Vacant(v) => {
                // Bind a fresh alias to the unit type.
                let slot_ref = self.module.typespace.add(AlgebraicType::unit());
                // Relate `typeid -> fresh alias`.
                v.insert(slot_ref);

                // Alias provided? Relate `name -> slot_ref`.
                if let Some(name) = name {
                    self.module.misc_exports.push(MiscModuleExport::TypeAlias(TypeAlias {
                        name: name.to_owned(),
                        ty: slot_ref,
                    }));
                }

                // Borrow of `v` has ended here, so we can now convince the borrow checker.
                let ty = make_ty(self);
                self.module.typespace[slot_ref] = ty;
                slot_ref
            }
        };
        AlgebraicType::Ref(r)
    }
}

// an enum to keep it extensible without breaking abi
#[derive(Debug, Clone, SpacetimeType)]
#[sats(crate = crate)]
pub enum MiscModuleExport {
    TypeAlias(TypeAlias),
}

#[derive(Debug, Clone, SpacetimeType)]
#[sats(crate = crate)]
pub struct TypeAlias {
    pub name: String,
    pub ty: sats::AlgebraicTypeRef,
}

/// Converts a hexadecimal string reference to a byte array.
///
/// This function takes a reference to a hexadecimal string and attempts to convert it into a byte array.
///
/// If the hexadecimal string starts with "0x", these characters are ignored.
pub fn from_hex_pad<R: hex::FromHex<Error = hex::FromHexError>, T: AsRef<[u8]>>(
    hex: T,
) -> Result<R, hex::FromHexError> {
    let hex = hex.as_ref();
    let hex = if hex.starts_with(b"0x") {
        &hex[2..]
    } else if hex.starts_with(b"X'") {
        &hex[2..hex.len()]
    } else {
        hex
    };
    hex::FromHex::from_hex(hex)
}

/// Returns a resolved `AlgebraicType` (containing no `AlgebraicTypeRefs`) for a given `SpacetimeType`,
/// using the v9 moduledef infrastructure.
/// Panics if the type is recursive.
///
/// TODO: we could implement something like this in `sats` itself, but would need a lightweight `TypespaceBuilder` implementation there.
pub fn resolved_type_via_v9<T: SpacetimeType>() -> AlgebraicType {
    let mut builder = RawModuleDefV9Builder::new();
    let ty = T::make_type(&mut builder);
    let module = builder.finish();

    WithTypespace::new(&module.typespace, &ty)
        .resolve_refs()
        .expect("recursive types not supported")
}

non_wasm! {
    /// one ore more concatenated certificated (ie. public) ie. a .crt file bundle
    pub const MAX_CERT_BUNDLE_SIZE:usize=1_048_576;//1MiB
    /// size of a private key file (contains 1 private key) ie. a .key file
    pub const MAX_KEY_FILE_SIZE:usize=64*1024;//64KiB
    pub async fn load_root_cert(cert_path: Option<&std::path::Path>) -> anyhow::Result<Option<native_tls::Certificate>> {
        if let Some(path) = cert_path {
            // Read file using read_file_limited
            let cert_data = read_file_limited(path, MAX_CERT_BUNDLE_SIZE)
                .await
                .context(format!("Failed to read certificate file: {}", path.display()))?;

            // Convert Vec<u8> to String for PEM parsing
            let cert_pem = String::from_utf8(cert_data)
                .context(format!("Certificate file is not valid UTF-8: {}", path.display()))?;

            // Parse PEM
            let cert = native_tls::Certificate::from_pem(cert_pem.as_bytes())
                .context(format!("Failed to parse PEM certificate: {}", path.display()))?;

            eprintln!("Added trusted certificate from {} for a new TLS connection.", path.display());
            Ok(Some(cert))
        } else {
            eprintln!("No trusted certificate specified via --cert for this new connection, thus if you used local CA or self-signed server certificate, you may get an error like '(unable to get local issuer certificate)' next.");
            Ok(None)
        }
    }

    //for cli clients:
    pub fn trust_server_cert() -> clap::Arg {
        //TODO: rename this to trust_ca_cert() it's less confusing
        clap::Arg::new("trust-server-cert")
            .long("trust-server-cert")
            .alias("trust-server-certs")
            .alias("trust-server-cert-bundle")
            .alias("cert")
            .alias("certs")
            .alias("cert-bundle")
            .alias("root-cert")
            .alias("root-certs")
            .alias("root-cert-bundle")
            .alias("trust-ca-cert")
            .alias("trust-ca-certs")
            .alias("trust-ca-cert-bundle")
            .alias("ca-certs")
            .alias("ca-cert")
            .alias("ca-cert-bundle")
            .value_name("FILE")
            .action(clap::ArgAction::Set)
            .value_parser(clap::value_parser!(std::path::PathBuf))
            .required(false)
            //        .requires("ssl")
            //.help("Path to PEM file containing certificates to trust for the server (e.g., CA or self-signed)")
            .help("Path to the server’s self-signed certificate or CA certificate (PEM format, can be a bundle ie. appended PEM certs) to trust during this command (ie. as if it were part of your system's cert trust/root store)")
    }

    //for the cli clients:
    pub fn client_cert() -> clap::Arg {
        clap::Arg::new("client-cert")
            .long("client-cert")
            .value_name("FILE")
            .action(clap::ArgAction::Set)
            .value_parser(clap::value_parser!(std::path::PathBuf))
            .required(false)
            .requires("client-key")
            .help("Path to the client’s certificate (PEM format) for authentication, this will be presented to the server that we(the client) are trying to connect to.")
    }

    //for the cli clients:
    pub fn client_key() -> clap::Arg {
        clap::Arg::new("client-key")
            .long("client-key")
            .value_name("FILE")
            .action(clap::ArgAction::Set)
            .value_parser(clap::value_parser!(std::path::PathBuf))
            .required(false)
            .requires("client-cert")
            .help("Path to the client’s private key (PEM format) for authentication, this will be used our(client) outgoing connection to the server.")
    }

    //for cli clients, this is the default(to trust):
    pub fn trust_system_root_store() -> clap::Arg {
        clap::Arg::new("trust-system-root-store")
            .long("trust-system-root-store")
            //        .alias("trust-root-store")
            .action(clap::ArgAction::SetTrue)
            .conflicts_with("no-trust-system-root-store")
            //        .requires("ssl")
            .help("Use system root certificates (default)")
    }

    //for cli clients, setting this means only the --trust-server-certs arg is used to verify the
    //target server's cert):
    pub fn no_trust_system_root_store() -> clap::Arg {
        clap::Arg::new("no-trust-system-root-store")
            .long("no-trust-system-root-store")
            .alias("empty-trust-store")
            //        .alias("no-trust-root-store")
            .action(clap::ArgAction::SetTrue)
            .conflicts_with("trust-system-root-store")
            .requires("trust-server-cert")
            .help("Use empty trust store (requires --trust-server-cert else there'd be 0 certs to verify trust)")
    }

    //for the standalone server:
    pub fn client_trust_cert() -> clap::Arg {
        clap::Arg::new("client-trust-cert")
            .long("client-trust-cert")
            .alias("client-cert")
            .alias("client-certs")
            .alias("client-ca-cert")
            .alias("client-CA-cert")
            .alias("client-root-cert")
            .alias("client-trust-certs")
            .alias("client-ca-certs")
            .alias("client-CA-certs")
            .alias("client-root-certs")
            .alias("client-cert-bundle")
            .alias("client-trust-cert-bundle")
            .alias("client-ca-cert-bundle")
            .alias("client-CA-cert-bundle")
            .alias("client-root-cert-bundle")
            .value_name("FILE")
            .action(clap::ArgAction::Set)
            .value_parser(clap::value_parser!(std::path::PathBuf))
            .requires("ssl")
            .required(false)
            .help("Path to PEM file containing certificate(s) to trust for client authentication (e.g., CA or self-signed)")
    }

    //for the standalone server:
    pub fn client_trust_system_root_store() -> clap::Arg {
        clap::Arg::new("client-trust-system-root-store")
            .long("client-trust-system-root-store")
            .action(clap::ArgAction::SetTrue)
            .conflicts_with("client-no-trust-system-root-store")
            .requires("ssl")
            .help("Use system root certificates for client authentication (unusual)")
    }

    //for the standalone server:
    pub fn client_no_trust_system_root_store() -> clap::Arg {
        clap::Arg::new("client-no-trust-system-root-store")
            .long("client-no-trust-system-root-store")
            .alias("client-empty-trust-store")
            .action(clap::ArgAction::SetTrue)
            .conflicts_with("client-trust-system-root-store")
            .requires("client-trust-cert")
            .requires("ssl")
            .help("Use empty trust store for client authentication (default), requires --client-trust-cert to validate client certs somehow.")
    }

    //This ensures data is zeroized on error paths (when ZeroizingVec is dropped) but allows returning the Vec on success without zeroizing.
    struct ZeroizingVec(Vec<u8>);

    impl ZeroizingVec {
        fn new(capacity: usize) -> Self {
            ZeroizingVec(Vec::with_capacity(capacity))
        }

        fn as_mut_vec(&mut self) -> &mut Vec<u8> {
            &mut self.0
        }

        fn into_inner(mut self) -> Vec<u8> {
            //std::mem::take<T>(dest: &mut T) -> T replaces the value at dest with a “default” value (for Vec<u8>, an empty Vec with zero capacity) and returns the original value.
            std::mem::take(&mut self.0)
            // Drop runs automatically, zeroizing the now-empty(and unallocated on heap) self.0 vec
        }
    }

    impl zeroize::ZeroizeOnDrop for ZeroizingVec {} // Marker
    impl Drop for ZeroizingVec {
        fn drop(&mut self) {
            //#[cfg(trace_drop_and_zeroize)] // set by ../build.rs if ring or pki-types have it set.
            if TRACE_DROP_AND_ZEROIZE {
                if self.0.len() > 0 {
                    eprintln!("!!! Dropping ZeroizingVec after zeroize-ing it.");
                } else {
                    eprintln!("!!! Dropping ZeroizingVec (empty)");
                }
            }
            self.0.zeroize();
        }
    }

    const MAX_BUF_SIZE:usize=64 * 1024; // 64KiB
    // Helper to zeroize a fixed-size buffer on drop
    struct ZeroizingBuffer([u8; MAX_BUF_SIZE]); // 64 KiB, matching Tokio's default chunk size

    impl ZeroizingBuffer {
        fn new() -> Self {
            ZeroizingBuffer([0u8; MAX_BUF_SIZE])
        }

        fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    impl zeroize::ZeroizeOnDrop for ZeroizingBuffer {} // Marker
    impl Drop for ZeroizingBuffer {
        fn drop(&mut self) {
            //#[cfg(feature = "trace_drop_and_zeroize")] // set by ../build.rs if ring or pki-types have it set.
            //#[cfg(trace_drop_and_zeroize)] // set by ../build.rs if ring or pki-types have it set.
            //XXX: can't really detect if ring(not in lib's Cargo.toml dep) or pki-types(it's in Cargo.toml) has trace_drop_and_zeroize feature since it's indirectly pulled by my_fork (unless I used my_fork=[] in pki-types or ring) but maybe it works via cargo metadata in build.rs, didn't try it. However, decided to use this const and toggle it by editing this source, if needed, ever.
            if TRACE_DROP_AND_ZEROIZE {
                if self.0.len() > 0 {
                    eprintln!("!!! Dropping ZeroizingBuffer after zeroize-ing it.");
                } else {
                    eprintln!("!!! Dropping ZeroizingBuffer (empty)");
                }
            }
            self.0.zeroize();
        }
    }

    fn smallest_non_zero(a: usize, b: usize) -> usize {
        assert!(a != 0 || b != 0, "both args were 0");
        if a == 0 {
            b
        } else if b == 0 {
            a
        } else {
            a.min(b)
        }
    }

    /// Asynchronously reads a file with a maximum size limit specified by max_size.
    /// If max_size is 0, no limit is applied (up to usize::MAX).
    /// Files up to and including max_size bytes are allowed; larger files will fail.
    /// Uses a temporary buffer to read chunks, allowing detection of extra data without over-allocating data.
    /// The internal buffer (which is temporary) is zeroized(on Drop) on error or success to prevent sensitive data lingering in memory.
    /// The returned data isn't zeroized, it's left for the caller to zeroize!
    pub async fn read_file_limited(path: &Path, max_size: usize) -> anyhow::Result<Vec<u8>> {
        let max_size = if max_size == 0 { usize::MAX } else { max_size };
        debug_assert!(max_size > 0);

        let mut file: tokio::fs::File = tokio::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .await
            .context(format!("Failed to open file: {}", path.display()))?;

        // This to avoid the reading/mem alloc-ing for normal eg. non-/dev/zero files:
        let metadata = file
            .metadata()
            .await
            .context(format!("Failed to read metadata for {}", path.display()))?;

        let f_len: usize = metadata
            .len()
            .try_into()
            .context(format!(
                    "File size for {} exceeds usize::MAX ({}) or is invalid",
                    path.display(),
                    usize::MAX
            ))?;

        if f_len > max_size {
            return Err(anyhow::anyhow!(
                    "File {} is {} bytes, which exceeds expected-maximum size of {} bytes",
                    path.display(),
                    f_len,
                    max_size
            ));
        }

        // blocks like /dev/zero are 0 bytes file len, thus then pick max_size instead.
        let max_read_len: usize = smallest_non_zero(f_len, max_size);
        // These are assert!, not debug_assert!, so they always execute, even in release builds, regardless of debug-assertions.
        assert!(max_read_len > 0, "max_read_len must be positive");

        let mut data = ZeroizingVec::new(max_read_len);
        let mut buffer = ZeroizingBuffer::new();
        let buf_slice:&mut [u8] = buffer.as_mut_slice();
        let buf_slice_len:usize=buf_slice.len();
        let mut total_read: usize = 0;

        // Read chunks into buffer, copy to data up to max_read_len
        while total_read < max_read_len {
            let to_read = (max_read_len - total_read).min(buf_slice_len);
            let n = file
                .read(&mut buf_slice[..to_read])
                .await
                .context(format!("Failed to read file: {}", path.display()))?;
            if n == 0 {
                debug_assert!(to_read > 0, "to_read must be positive for n == 0 to indicate EOF");
                break; // EOF
            }
            data.as_mut_vec().extend_from_slice(&buf_slice[..n]);
            total_read += n;
        }

        // Check for extra data by attempting to read one more byte into the buffer
        if total_read == max_read_len {
            let n = file
                .read(&mut buf_slice[..1])
                .await
                .context(format!("Failed to check for extra data: {}", path.display()))?;
            if n > 0 && max_read_len == max_size {
                return Err(anyhow::anyhow!(
                        "File {} has more data after reading {} bytes, exceeding maximum size of {} bytes",
                        path.display(),
                        max_read_len,
                        max_size
                ));
            }
        }

        // Buffer is zeroized automatically on drop (success or error)
        // but 'data' isn't, well the Vec<u8> we return is caller's problem to zeroize now.
        Ok(data.into_inner())
    }

    #[macro_export]
    macro_rules! set_string {
        ($s:expr, $new:expr) => {
            $s.replace_range(.., $new);
        };
    }

    pub fn set_string(s: &mut String, new: &str) {
        s.replace_range(.., new);
    }

    #[macro_export]
    macro_rules! new_string {
        ($binding:ident, $initial:literal, $capacity:expr) => {
            let mut $binding: String = {
                const LOCAL: &str = $initial; // Explicit &str
                let capacity: usize = const {
                    // Compile-time check
                    const INIT_LEN: usize = $initial.len();
                    if $capacity >= INIT_LEN { $capacity } else { INIT_LEN }
                };
                let mut s: String = String::with_capacity(capacity);
                s.push_str(LOCAL);
                //FIXME Move: Returns a String (24 bytes: ptr, len, capacity), moved to $binding.
                //--release: LLVM inlines the block, constructing s directly in $binding’s stack slot (zero cost). The move is eliminated—s is built in-place.
                s
            };
        };
        ($binding:ident, $initial:expr, $capacity:expr) => {
            let mut $binding: String = {
                let local: &str = $initial; // Explicit &str
                let capacity: usize = {
                    // Runtime check
                    let init_len = local.len();
                    if $capacity >= init_len { $capacity } else { init_len }
                };
                let mut s: String = String::with_capacity(capacity);
                s.push_str(local);
                //FIXME Move: Returns a String (24 bytes: ptr, len, capacity), moved to $binding.
                //--release: LLVM inlines the block, constructing s directly in $binding’s stack slot (zero cost). The move is eliminated—s is built in-place.
                s
            };
        };
    }

    use std::path::Path;
    use std::error::Error;

    #[derive(Debug)]
    pub struct ClientCertError {
        path: String,
        source: anyhow::Error,
    }

    impl ClientCertError {
        pub fn new(path: &Path, source: anyhow::Error) -> Self {
            Self {
                path: path.display().to_string(),
                source,
            }
        }
    }

    impl std::fmt::Display for ClientCertError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Something failed with client certificate {}", self.path) //: {}", self.path, self.source)
        }
    }

    impl Error for ClientCertError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&*self.source)
        }
    }

    #[derive(Debug)]
    pub struct ClientKeyError {
        path: String,
        source: anyhow::Error,
    }

    impl ClientKeyError {
        pub fn new(path: &Path, source: anyhow::Error) -> Self {
            Self {
                path: path.display().to_string(),
                source,
            }
        }
    }

    impl std::fmt::Display for ClientKeyError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Something failed with client private key {}", self.path) //: {}", self.path, self.source)
        }
    }

    impl Error for ClientKeyError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&*self.source)
        }
    }

    #[derive(Debug)]
    pub struct TrustCertError {
        path: String,
        source: anyhow::Error,
    }

    impl TrustCertError {
        pub fn new(path: &Path, source: anyhow::Error) -> Self {
            Self {
                path: path.display().to_string(),
                source,
            }
        }
    }

    impl std::fmt::Display for TrustCertError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Something failed with trust certificate {}", self.path) //: {}", self.path, self.source)
        }
    }

    impl Error for TrustCertError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            Some(&*self.source)
        }
    }

    /*doneFIXME: find out why I got the following error only once.
      ok it's this https://github.com/seanmonstar/reqwest/issues/1808 and possibly https://github.com/hyperium/hyper/issues/2136  but basically it's because client doesn't expect server to reply because client didn't request(HTTP1) anything first in order to expect a reply, so if both  reply and close  are happening on server then some race happens where mostly closed connection is handled first, even tho the reply itself is already gotten.
     * https://github.com/seanmonstar/reqwest/issues/2649
     * https://github.com/hyperium/hyper-util/pull/184
     *
     $ spacetime server ping slocal --cert ../my/spacetimedb-cert-gen/ca.crt
     WARNING: This command is UNSTABLE and subject to breaking changes.

     Adding trusted root cert(for server verification): subject=CN=MyLocalCA, issuer=CN=MyLocalCA, serial=359627719638463223090969970838819027680303337392, expires=Mar 24 13:24:50 2035 +00:00, fingerprint=25bb314ec76db8ab97f225011ec24dd0bca8aff470cb21c812600a8f4ed0cca7
     Error: Failed sending request to https://127.0.0.1:3000: Failed to construct or send the HTTP request, source: Some(
     hyper_util::client::legacy::Error(
     Canceled,
     hyper::Error(
     Canceled,
     hyper::Error(
     Io,
     Custom {
     kind: Other,
     error: Error {
     code: ErrorCode(
     1,
     ),
     cause: Some(
     Ssl(
     ErrorStack(
     [
     Error {
     code: 167773276,
     library: "SSL routines",
     function: "ssl3_read_bytes",
     reason: "tlsv13 alert certificate required",
     file: "ssl/record/rec_layer_s3.c",
     line: 908,
     data: "SSL alert number 116",
     },
     ],
     ),
     ),
     ),
     },
     },
     ),
     ),
     ),
     )


     XXX: and why I get instead this:

     $ spacetime server ping slocal --cert ../my/spacetimedb-cert-gen/ca.crt
     WARNING: This command is UNSTABLE and subject to breaking changes.

     Adding trusted root cert(for server verification): subject=CN=MyLocalCA, issuer=CN=MyLocalCA, serial=359627719638463223090969970838819027680303337392, expires=Mar 24 13:24:50 2035 +00:00, fingerprint=25bb314ec76db8ab97f225011ec24dd0bca8aff470cb21c812600a8f4ed0cca7
     Error: Failed sending request to https://127.0.0.1:3000: Server closed the connection because you did NOT provide the args --client-cert and --client-key for mutual TLS (mTLS), source: Some(
     hyper_util::client::legacy::Error(
     SendRequest,
     hyper::Error(
     ChannelClosed,
     ),
     ),
     )
    */
    pub fn map_request_error<E: Into<anyhow::Error>>(
        e: E,
        url: &String,
        client_cert_path: Option<&Path>,
        client_key_path: Option<&Path>,
    ) -> anyhow::Error {
        let e = e.into();
        //let mut last_message:String = "Unknown error occurred".to_string();
        new_string!(last_message, "An error occurred that wasn't mapped into something better by map_request_error.", 512);
        //    fn example<E: std::fmt::Display>(e: &E) -> String {
        //        format!("err: {}, Error type: {}", e, std::any::type_name::<E>())
        //    }
        //    set_string!(last_message, &format!("{}", example(&e)));
        let mut max_specificity = 0; // 0: Unknown, 1: reqwest, 2: ChannelClosed, 3: tlsv13 alert, 4: file

        /*Normally Similar: For most types, &e and e.as_ref() are equivalent, as AsRef often just returns a reference to the type. For example, for String, e.as_ref() returns &String, same as &e.
          Your Case: For anyhow::Error, e.as_ref() is special:

          &e gives &anyhow::Error, a reference to the struct.
          e.as_ref() calls anyhow::Error’s AsRef implementation, returning &dyn std::error::Error + Send + Sync + 'static. This dynamic trait object satisfies the bounds needed for downcast_ref and source, avoiding E0277.
          */
        // Summary: e.as_ref() in map_request_error converts e: anyhow::Error to &dyn std::error::Error, enabling safe chain traversal.
        // Traverse the error chain using e.as_ref()
        let mut current: Option<&dyn std::error::Error> = Some(e.as_ref());
        while let Some(err) = current {
            // Check hyper::Error
            if let Some(hyper_err) = err.downcast_ref::<hyper::Error>() {
                if hyper_err.is_closed() {
                    let msg = (
                        if client_cert_path.is_none() || client_key_path.is_none() {
                            "Server closed the connection likely because you did NOT provide the args --client-cert and --client-key for mutual TLS (mTLS) and server requires it, also you need the hyper-util patch which affects hyper/reqwest and makes them not hide connection errors behind ChannelClosed from here: https://github.com/hyperium/hyper-util/pull/184 which means that's why you're seeing this generic error."
                        } else {
                            "Connection channel closed unexpectedly (server may be down or misconfigured), you should have this PR https://github.com/hyperium/hyper-util/pull/184 applied to avoid hiding the real reason behind ChannelClosed error(s)."
                        },
                        2,
                    );
                    if msg.1 > max_specificity {
                        //last_message = msg.0.to_string();
                        //last_message. = msg.0.to_string();
                        set_string!(last_message, msg.0);
                        max_specificity = msg.1;
                    }
                }
                if let Some(io_err) = hyper_err.source() {
                    if let Some(ssl_err) = io_err.downcast_ref::<std::io::Error>() {
                        if let Some(openssl_err) = ssl_err.get_ref() {
                            if let Some(ssl_error) = openssl_err.downcast_ref::<openssl::ssl::Error>() {
                                // BEGIN: Refactored OpenSSL error stack iteration to check multiple reasons
                                if let Some(stack) = ssl_error.ssl_error() {
                                    for e in stack.errors() {
                                        if e.reason() == Some("tlsv13 alert certificate required") {
                                            let msg = (
                                                if client_cert_path.is_none() || client_key_path.is_none() {
                                                    "You didn't pass the required client certificate(yours) for mTLS, use --client-cert and --client-key 🔒"
                                                } else {
                                                    "TLS handshake failed: server requires a valid client certificate(yours) for mTLS 🔒"
                                                },
                                                3,
                                            );
                                            if msg.1 > max_specificity {
                                                set_string!(last_message, msg.0);
                                                max_specificity = msg.1;
                                            }
                                        }
                                        if e.reason() == Some("tlsv1 alert unknown ca") {
                                            assert!(client_cert_path.is_some() && client_key_path.is_some(),"dev error, this should be unreachable: TLS handshake failed: server requires a client certificate for mTLS, but none was provided. Use --client-cert and --client-key with valid files.");
                                            let msg = (
                                                    "TLS handshake failed: the server does not trust the CA that signed your client certificate. Ensure the server is configured with the correct CA certificate via --client-trust-cert (the CA that signed your client1.crt, e.g., ca4clients.crt)."
                                                ,
                                                3,
                                            );
                                            if msg.1 > max_specificity {
                                                set_string!(last_message, msg.0);
                                                max_specificity = msg.1;
                                            }
                                        }//if
                                    }//for
                                }//if
                            }//if
                        }//if
                    }//if
                }//if
            }//if
            // Check reqwest::Error
            else if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
                let msg = if reqwest_err.is_connect() {
                    Some(("Failed to connect to the server (connection refused or network unreachable)", 1))
                } else if reqwest_err.is_timeout() {
                    Some(("Request timed out while trying to reach the server", 1))
                } else if reqwest_err.is_request() {
                    Some(("Failed to construct or send the HTTP request", 1))
                } else if reqwest_err.is_body() {
                    Some(("Error in the request body", 1))
                } else if reqwest_err.is_decode() {
                    Some(("Failed to decode the response", 1))
                } else {
                    None
                };
                if let Some((msg, spec)) = msg {
                    if spec > max_specificity {
                        //last_message = msg;
                        set_string!(last_message, msg);
                        max_specificity = spec;
                    }
                }
            }
            // Check custom file errors
            else if let Some(trust_err) = err.downcast_ref::<TrustCertError>() {
                let msg = (format!("problem with trust certificate file {}", trust_err.path), 4);
                if msg.1 > max_specificity {
                    set_string!(last_message, &msg.0);
                    max_specificity = msg.1;
                }
            }
            else if let Some(cert_err) = err.downcast_ref::<ClientCertError>() {
                let msg = (format!("problem with client certificate file {}", cert_err.path), 4);
                if msg.1 > max_specificity {
                    set_string!(last_message, &msg.0);
                    max_specificity = msg.1;
                }
            }
            else if let Some(key_err) = err.downcast_ref::<ClientKeyError>() {
                let msg = (format!("problem with client private key file {}", key_err.path), 4);
                if msg.1 > max_specificity {
                    set_string!(last_message, &msg.0);
                    max_specificity = msg.1;
                }
            }

            current = err.source();
        }
        //TODO: see if specificity is needed, and likely get rid of it

        let source_str = match e.source() {
            Some(err) => format!("{:#?}", err),
            None => "<no error cause/source>".to_string(),
        };
        let message=format!(
            "(as follows on next lines)\n------- map_request_error ------\nFailed sending request to {}\nerr   : {}\nsource: {}\n----- end -----",
            url,
            last_message,
            source_str,
        );
        // Chain the original error with the new message
        e.context(message)
    }

    #[macro_export]
    macro_rules! map_request_error {
        ($result:expr, $url:expr, $client_cert_path:expr, $client_key_path:expr) => {
            //using self:: here requires only an use spacetimedb_lib::map_request_error; at call site.
            //and note how macro and fn name are same.
            $result.map_err(|e| self::map_request_error(e,
                    &$url,
                    $client_cert_path.as_deref(),
                    $client_key_path.as_deref()
            ))
        };
    }


    #[cfg(test)]
    mod tests {
        use super::{read_file_limited, MAX_BUF_SIZE};
        use anyhow::Context;
        use std::path::Path;
        use tempfile::NamedTempFile;
        use tokio::fs::File;
        use tokio::io::AsyncWriteExt;

        const TEST_MAX_SIZE: usize = 1_048_576; // 1 MiB

        // Tests for MAX_BUF_SIZE multiples (1x, 2x, 3x) with -1, 0, +1 bytes
        #[tokio::test]
        async fn test_1x_buf_size_minus_1() {
            let size = MAX_BUF_SIZE - 1; // 65,535
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_1x_buf_size() {
            let size = MAX_BUF_SIZE; // 65,536
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_1x_buf_size_plus_1() {
            let size = MAX_BUF_SIZE + 1; // 65,537
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_2x_buf_size_minus_1() {
            let size = 2 * MAX_BUF_SIZE - 1; // 131,071
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_2x_buf_size() {
            let size = 2 * MAX_BUF_SIZE; // 131,072
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_2x_buf_size_plus_1() {
            let size = 2 * MAX_BUF_SIZE + 1; // 131,073
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_3x_buf_size_minus_1() {
            let size = 3 * MAX_BUF_SIZE - 1; // 196,607
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_3x_buf_size() {
            let size = 3 * MAX_BUF_SIZE; // 196,608
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_3x_buf_size_plus_1() {
            let size = 3 * MAX_BUF_SIZE + 1; // 196,609
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        // Helper to create a file with a specific size
        async fn create_test_file(size: usize) -> anyhow::Result<NamedTempFile> {
            let temp_file = NamedTempFile::new().context("Failed to create temp file")?;
            let mut file = File::create(temp_file.path()).await.context("Failed to open temp file")?;
            let data = vec![0u8; size];
            file.write_all(&data).await.context("Failed to write to temp file")?;
            file.flush().await.context("Failed to flush temp file")?;
            Ok(temp_file)
        }

        #[tokio::test]
        async fn test_max_allowed_size() {
            // Test a file of 1,048,575 bytes (TEST_MAX_SIZE - 1, should succeed)
            let temp_file = create_test_file(TEST_MAX_SIZE - 1)
                .await
                .expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", TEST_MAX_SIZE - 1, result);
            let data = result.unwrap();
            assert_eq!(data.len(), TEST_MAX_SIZE - 1, "Expected {} bytes, got {}", TEST_MAX_SIZE - 1, data.len());
        }

        #[tokio::test]
        async fn test_exactly_max_size() {
            // Test a file of 1,048,576 bytes (TEST_MAX_SIZE, should succeed)
            let temp_file = create_test_file(TEST_MAX_SIZE)
                .await
                .expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", TEST_MAX_SIZE, result);
            let data = result.unwrap();
            assert_eq!(data.len(), TEST_MAX_SIZE, "Expected {} bytes, got {}", TEST_MAX_SIZE, data.len());
        }

#[tokio::test]
        async fn test_dev_zero() {
            // Test /dev/zero (special file, should fail due to extra data)
            let path = Path::new("/dev/zero");
            if path.exists() {
                let result = read_file_limited(path, TEST_MAX_SIZE).await;
                assert!(result.is_err(), "Expected failure for /dev/zero, got {:?}", result);
                let err = result.unwrap_err().to_string();
                assert!(
                    err.contains("has more data"),
                    "Expected extra data error, got {}",
                    err
                );
            } else {
                eprintln!("Skipping /dev/zero test: file does not exist");
            }
        }

        #[tokio::test]
        async fn test_empty_file() {
            // Test an empty file (0 bytes, should succeed)
            let temp_file = NamedTempFile::new().expect("Failed to create temp file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for empty file, got {:?}", result);
            let data = result.unwrap();
            assert_eq!(data.len(), 0, "Expected 0 bytes, got {}", data.len());
        }

        #[tokio::test]
        async fn test_small_file() {
            // Test a small file (2 KiB, should succeed)
            let size = 2 * 1024; // 2 KiB
            let temp_file = create_test_file(size).await.expect("Failed to create test file");
            let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
            assert!(result.is_ok(), "Expected success for {} bytes, got {:?}", size, result);
            let data = result.unwrap();
            assert_eq!(data.len(), size, "Expected {} bytes, got {}", size, data.len());
        }

        #[tokio::test]
        async fn test_content_verification() {
            // Test files of various sizes, verifying content matches expected pattern
            let sizes = [
                0,                 // Empty file
                1,                 // Single byte
                1024,              // 1 KiB
                MAX_BUF_SIZE - 1,  // 65,535 (1x MAX_BUF_SIZE - 1)
                MAX_BUF_SIZE,      // 65,536 (1x MAX_BUF_SIZE)
                MAX_BUF_SIZE + 1,  // 65,537 (1x MAX_BUF_SIZE + 1)
                2 * MAX_BUF_SIZE - 1, // 131,071 (2x MAX_BUF_SIZE - 1)
                2 * MAX_BUF_SIZE,     // 131,072 (2x MAX_BUF_SIZE)
                2 * MAX_BUF_SIZE + 1, // 131,073 (2x MAX_BUF_SIZE + 1)
                3 * MAX_BUF_SIZE - 1, // 196,607 (3x MAX_BUF_SIZE - 1)
                3 * MAX_BUF_SIZE,     // 196,608 (3x MAX_BUF_SIZE)
                3 * MAX_BUF_SIZE + 1, // 196,609 (3x MAX_BUF_SIZE + 1)
            ];

            for &size in sizes.iter() {
                // Create file with deterministic content
                let temp_file = NamedTempFile::new().expect("Failed to create temp file");
                //{
                    let mut file = File::create(temp_file.path())
                    .await
                    .expect("Failed to open temp file");
                    let mut data: Vec<u8> = Vec::with_capacity(size);
                    for i in 0..size {
                        data.push((i % 256) as u8); // Repeating pattern [0, 1, 2, ..., 255, 0, ...]
                    }
                    file.write_all(&data)
                        .await
                        .expect("Failed to write to temp file");
                    //file.flush().await.expect("Failed to flush temp file");
                drop(file); // Explicitly close the file
                //}//drop 'file' which should close it.

                // Read file and verify content
                let result = read_file_limited(temp_file.path(), TEST_MAX_SIZE).await;
                assert!(
                    result.is_ok(),
                    "Expected success for {} bytes, got {:?}",
                    size,
                    result
                );
                let read_data = result.unwrap();
                assert_eq!(
                    read_data.len(),
                    size,
                    "Expected {} bytes, got {} bytes",
                    size,
                    read_data.len()
                );
                for (i, &byte) in read_data.iter().enumerate() {
                    assert_eq!(
                        byte,
                        (i % 256) as u8,
                        "Content mismatch at index {} for size {}",
                        i,
                        size
                    );
                }
            }
        }

        use zeroize::ZeroizeOnDrop;
        use super::{ZeroizingVec, ZeroizingBuffer};

        #[test]
        fn test_has_zeroize_on_drop() {
            const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
            assert_zeroize_on_drop::<ZeroizingVec>();
            assert_zeroize_on_drop::<ZeroizingBuffer>();
        }
    }//mod tests

} // end of non_wasm! macro call
