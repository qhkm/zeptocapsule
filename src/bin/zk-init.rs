fn main() {
    if let Err(error) = zeptocapsule::run_init_shim() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
