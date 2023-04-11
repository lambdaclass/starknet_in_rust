use std::{fs, path::Path};

fn recursive_copy(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;
    let dir = fs::read_dir(src)?;
    for entry in dir {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            recursive_copy(
                entry.path().as_path(),
                dst.join(entry.file_name()).as_path(),
            )?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let src = Path::new("corelib/");
    let dst = Path::new("target/debug/corelib");
    recursive_copy(src, dst)
}
