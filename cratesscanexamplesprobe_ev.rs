fn main() {
    use kotama::AddressSpace;
    for name in ["calls_a64", "ctrl_a64_macho", "stripped_a64"] {
        let bytes = std::fs::read(std::path::Path::new(r"D:???????celestia_scratchkotama-formats-probe").join(name)).unwrap();
        let m = kotama_image::LoadedModule::parse(&bytes).unwrap();
        let fns = kotama_scan::discover(&m);
        let _ = m.address_space();
        println!("{name}:");
        for f in &fns {
            let ev: Vec<&str> = f.evidence.iter().map(|e| e.short()).collect();
            println!("   {:#x} size={} name={:?} ev={:?}", f.rva, f.size, f.name, ev);
        }
    }
}
