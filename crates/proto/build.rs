fn main() {
    // capnpc emits no cargo directives itself; without this every edit in the crate regenerates the schema.
    println!("cargo:rerun-if-changed=schema/jackalopefs.capnp");
    println!("cargo:rerun-if-changed=schema/control.capnp");
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/jackalopefs.capnp")
        .file("schema/control.capnp")
        .run()
        .expect("compiling the schemas in schema/ (is the `capnp` compiler installed?)");
}
