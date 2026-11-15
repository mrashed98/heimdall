use std::{env, fs, path::Path};

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
fn main() {
    println!("cargo:rerun-if-changed=web/dist");
    let out = std::path::PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("ui");
    if out.exists() {
        fs::remove_dir_all(&out).unwrap();
    }
    fs::create_dir_all(&out).unwrap();
    let dist = Path::new("web/dist");
    if dist.join("index.html").is_file() {
        copy_dir(dist, &out).unwrap();
    } else {
        fs::write(
            out.join("index.html"),
            "<!doctype html><html><body>UI not built; run npm run build in web/</body></html>",
        )
        .unwrap();
    }
    let source = format!(
        "#[derive(rust_embed::RustEmbed)]\n#[folder = {:?}]\nstruct UiAssets;\n",
        format!("{}/", out.display())
    );
    fs::write(out.parent().unwrap().join("ui_embed.rs"), source).unwrap();
}
