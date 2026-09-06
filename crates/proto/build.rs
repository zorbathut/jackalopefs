fn main() {
    // capnpc emits no cargo directives itself; without this every edit in the crate regenerates the schema.
    println!("cargo:rerun-if-changed=schema/jackalopefs.capnp");
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/jackalopefs.capnp")
        .run()
        .expect("compiling schema/jackalopefs.capnp (is the `capnp` compiler installed?)");
}
