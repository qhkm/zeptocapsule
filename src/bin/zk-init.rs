fn main() {
    if let Err(error) = zeptokernel::run_init_shim() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
