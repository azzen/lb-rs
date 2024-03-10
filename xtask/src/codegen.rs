use std::{fs::File, io::Write, path::PathBuf};

use aya_tool::generate::InputFile;


pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("load-balancer-ebpf/src");
    let names = vec!["ethhdr", "iphdr", "udphdr"];
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    let mut output = File::create(dir.join("bindings.rs"))?;
    write!(output, "{}", bindings)?;
    Ok(())
}