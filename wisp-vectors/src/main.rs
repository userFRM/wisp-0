use std::fs;
use std::path::Path;

use wisp_vectors::*;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "generate" => generate(),
        "verify" => verify(),
        _ => {
            eprintln!("Usage: wisp-vectors <generate|verify>");
            std::process::exit(1);
        }
    }
}

fn generate() {
    let dir = Path::new("vectors");
    fs::create_dir_all(dir).expect("failed to create vectors/");

    let cdc = generate_cdc_vectors();
    fs::write(
        dir.join("cdc.json"),
        serde_json::to_string_pretty(&cdc).unwrap(),
    )
    .unwrap();
    eprintln!("Wrote vectors/cdc.json ({} vectors)", cdc.len());

    let recipe = generate_recipe_vectors();
    fs::write(
        dir.join("recipe.json"),
        serde_json::to_string_pretty(&recipe).unwrap(),
    )
    .unwrap();
    eprintln!("Wrote vectors/recipe.json ({} vectors)", recipe.len());

    let ict = generate_ict_vectors();
    fs::write(
        dir.join("ict.json"),
        serde_json::to_string_pretty(&ict).unwrap(),
    )
    .unwrap();
    eprintln!("Wrote vectors/ict.json ({} vectors)", ict.len());

    let ssx = generate_ssx_vectors();
    fs::write(
        dir.join("ssx.json"),
        serde_json::to_string_pretty(&ssx).unwrap(),
    )
    .unwrap();
    eprintln!("Wrote vectors/ssx.json ({} vectors)", ssx.len());

    let e2e = generate_e2e_vectors();
    fs::write(
        dir.join("e2e.json"),
        serde_json::to_string_pretty(&e2e).unwrap(),
    )
    .unwrap();
    eprintln!("Wrote vectors/e2e.json ({} vectors)", e2e.len());

    eprintln!("All vectors generated.");
}

fn verify() {
    let dir = Path::new("vectors");

    let cdc: Vec<CdcVector> =
        serde_json::from_str(&fs::read_to_string(dir.join("cdc.json")).expect("read cdc.json"))
            .expect("parse cdc.json");
    match verify_cdc_vectors(&cdc) {
        Ok(()) => eprintln!("CDC: OK ({} vectors)", cdc.len()),
        Err(e) => {
            eprintln!("CDC: FAIL: {}", e);
            std::process::exit(1);
        }
    }

    let recipe: Vec<RecipeVector> = serde_json::from_str(
        &fs::read_to_string(dir.join("recipe.json")).expect("read recipe.json"),
    )
    .expect("parse recipe.json");
    match verify_recipe_vectors(&recipe) {
        Ok(()) => eprintln!("Recipe: OK ({} vectors)", recipe.len()),
        Err(e) => {
            eprintln!("Recipe: FAIL: {}", e);
            std::process::exit(1);
        }
    }

    let ict: Vec<IctVector> =
        serde_json::from_str(&fs::read_to_string(dir.join("ict.json")).expect("read ict.json"))
            .expect("parse ict.json");
    match verify_ict_vectors(&ict) {
        Ok(()) => eprintln!("ICT: OK ({} vectors)", ict.len()),
        Err(e) => {
            eprintln!("ICT: FAIL: {}", e);
            std::process::exit(1);
        }
    }

    let ssx: Vec<SsxVector> =
        serde_json::from_str(&fs::read_to_string(dir.join("ssx.json")).expect("read ssx.json"))
            .expect("parse ssx.json");
    match verify_ssx_vectors(&ssx) {
        Ok(()) => eprintln!("SSX: OK ({} vectors)", ssx.len()),
        Err(e) => {
            eprintln!("SSX: FAIL: {}", e);
            std::process::exit(1);
        }
    }

    let e2e: Vec<E2eVector> =
        serde_json::from_str(&fs::read_to_string(dir.join("e2e.json")).expect("read e2e.json"))
            .expect("parse e2e.json");
    match verify_e2e_vectors(&e2e) {
        Ok(()) => eprintln!("E2E: OK ({} vectors)", e2e.len()),
        Err(e) => {
            eprintln!("E2E: FAIL: {}", e);
            std::process::exit(1);
        }
    }

    eprintln!("All vectors verified.");
}
