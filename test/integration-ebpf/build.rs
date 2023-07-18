use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let bpf_linker = env::var("CARGO_BIN_FILE_BPF_LINKER").unwrap();

    // There seems to be no way to pass `-Clinker={}` to rustc from here.
    //
    // We assume rustc is going to look for `bpf-linker` on the PATH, so we can create a symlink and
    // put it on the PATH.
    let bin_dir = out_dir.join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let bpf_linker_symlink = bin_dir.join("bpf-linker");
    match fs::remove_file(&bpf_linker_symlink) {
        Ok(()) => {}
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                panic!("failed to remove symlink: {err}")
            }
        }
    }
    std::os::unix::fs::symlink(bpf_linker, bpf_linker_symlink).unwrap();
    let path = env::var_os("PATH");
    let path = path.as_ref();
    let paths = std::iter::once(bin_dir).chain(path.into_iter().flat_map(env::split_paths));
    let path = env::join_paths(paths).unwrap();
    println!("cargo:rustc-env=PATH={}", path.to_str().unwrap());
}
