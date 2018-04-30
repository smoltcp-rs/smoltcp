use std::process::Command;
use std::env;

fn main() {
  let out_dir = env::var("OUT_DIR").unwrap();
  let _out = Command::new("cp")
        .arg("libfirewall.a")
        .arg(out_dir + "/.")
        .output()
        .expect("failed to execute process");


  let out_dir = env::var("OUT_DIR").unwrap();
  let _out = Command::new("cp")
        .arg("libserver.a")
        .arg(out_dir + "/.")
        .output()
        .expect("failed to execute process");

  let out_dir = env::var("OUT_DIR").unwrap();		
  println!("cargo:rustc-link-search={}",out_dir);
  println!("cargo:rustc-link-lib=firewall");
  println!("cargo:rustc-link-lib=server");		

}

