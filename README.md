# iroh-persist

Library to persist Iroh secret keys.

Build a command-line app with [clap](https://docs.rs/clap/latest/clap/) and
declare a struct for common arguments like this:
```rust
#[derive(Parser, Debug)]
pub struct CommonArgs {
    /// Use a persistent node key pair
    #[arg(long)]
    persist: bool,
    /// Write and read the node keys at the given location
    #[arg(long)]
    persist_at: Option<PathBuf>,
    /// More arguments...
}
```

Then use the parsed flags (assumed they ended up in a variable named `common`)
like so:
```rust
let secret_key = iroh_persist::KeyRetriever::new("my-app")
    .persist(common.persist)
    .persist_at(common.persist_at.as_ref())
    .get()
    .await;
let endpoint = Endpoint::builder().secret_key(secret_key).bind().await?;
```

If you used to invoke:
```shell
IROH_SECRET=<hex-key> my-app args...
```
Then invoke this at least once:
```shell
IROH_SECRET=<hex-key> my-app --persist args...
```
Then iroh-persist will save the key on disk. After that, this invocation
will suffice:
```shell
my-app --persist args...
```

Use `--persist-at <file>` instead of `--persist` if you need mote than one
secret key for the same app.

To debug, invoke the app with:
```rust
RUST_LOG=debug my-app --persist args...
```
