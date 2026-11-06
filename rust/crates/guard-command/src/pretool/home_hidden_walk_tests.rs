/// `find ~/.nvm -type d` is bounded by nothing but the entry kind, so it
/// prints whatever directory the tree holds, at whatever depth. A store
/// directly below the tool directory would have its own layout printed that
/// way, so the root's entries are screened before the walk is proven; a root
/// whose entries hold no store keeps the inventory it was taken for.
#[test]
fn a_store_below_a_tool_directory_stops_an_unbounded_walk() {
    let root =
        std::path::Path::new("/tmp").join(format!("guard-walk-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let home = root.join("home");
    let workspace = home.join("project");
    let toolchain = home.join(".nvm");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::create_dir_all(workspace.join(".git")).unwrap();
    std::fs::create_dir_all(toolchain.join("versions")).unwrap();
    // A hook hands over the home and working directories as the host spells
    // them. On Windows `std::fs::canonicalize` adds a `\\?\` prefix that no
    // hook sends, and the spelling screen refuses its `?`.
    let home = crate::runtime_read_paths::canonicalize_text(&home).unwrap();
    let workspace = crate::runtime_read_paths::canonicalize_text(&workspace).unwrap();
    let (home_dir, cwd) = (home.to_str(), workspace.to_str());

    assert!(super::home_hidden_walk_clears_stores(
        home.join(".nvm").to_str().unwrap(),
        home_dir,
        cwd
    ));

    std::fs::create_dir_all(home.join(".nvm").join(".aws")).unwrap();
    assert!(!super::home_hidden_walk_clears_stores(
        home.join(".nvm").to_str().unwrap(),
        home_dir,
        cwd
    ));

    let _ = std::fs::remove_dir_all(&root);
}
