use super::*;
use std::time::Duration;

const ON: &str = "[context_assistance]\nenabled=true\nruntime_id='selected'\n\
[context_assistance.features]\nagent_context=true\n\
[context_assistance.sources]\nworkspace_documents=true\nsource_set_id='selected-workspaces'\n";

struct Fixture {
    home: tempfile::TempDir,
    _project: tempfile::TempDir,
    root: std::path::PathBuf,
}

fn fixture(config: &str) -> Fixture {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), config).unwrap();
    let project = tempfile::tempdir().unwrap();
    let root = crate::context_assistance_prompt_files::plain(
        std::fs::canonicalize(project.path()).unwrap(),
    );
    std::fs::create_dir_all(root.join("src")).unwrap();
    Fixture {
        home,
        _project: project,
        root,
    }
}

impl Fixture {
    fn write(&self, relative: &str, text: &str) {
        std::fs::write(self.root.join(relative), text).unwrap();
    }

    fn read(&self, found: &[&str], words: &[&str]) -> Vec<PickedExcerpt> {
        self.read_named(found, words).0
    }

    fn read_named(&self, found: &[&str], words: &[&str]) -> (Vec<PickedExcerpt>, Vec<String>) {
        let found: Vec<String> = found.iter().map(|path| (*path).to_owned()).collect();
        let words: Vec<String> = words.iter().map(|word| (*word).to_owned()).collect();
        let until = Instant::now() + Duration::from_secs(5);
        quick_excerpts(
            self.home.path(),
            &self.root,
            "claude-code",
            &found,
            &words,
            8,
            until,
        )
    }
}

fn file(path: &str, chunks: &[(&str, u32)]) -> AdmittedFile {
    AdmittedFile {
        source_id: format!("source:{path}"),
        relative_path: path.into(),
        sha256: String::new(),
        documents: chunks
            .iter()
            .enumerate()
            .map(|(index, (text, start_line))| ContextDocument {
                id: format!("doc:{path}:{index}"),
                text: (*text).into(),
                start_line: *start_line,
            })
            .collect(),
    }
}

#[test]
fn the_best_part_holds_the_most_words_and_the_earliest_wins_a_tie() {
    let words = vec!["cart".to_owned(), "total".to_owned()];
    let cart = file(
        "src/cart.ts",
        &[
            ("export const cart = [];\n", 1),
            ("export function cartTotal() {\n  return 0;\n}\n", 20),
            ("// cart total again\n", 40),
        ],
    );
    let (score, part) = best_part(&cart, &words).unwrap();
    assert_eq!(score, 2);
    assert_eq!((part.start_line, part.end_line), (20, 22));
    assert!(part.text.contains("cartTotal"));
    let none = file("src/theme.ts", &[("export const colors = {};\n", 1)]);
    assert!(best_part(&none, &words).is_none());
}

/// The first prompt of a session, with CIGAR still starting, gets the code
/// it is about instead of a list of file names.
#[test]
fn a_starting_cigar_still_gives_the_prompt_the_matched_code() {
    let f = fixture(ON);
    f.write(
        "src/cart.ts",
        "export interface CartItem { price: number; qty: number }\n\
         export function cartTotal(items: CartItem[]): number {\n\
         \x20 return items.reduce((sum, item) => sum + item.price * item.qty, 0);\n}\n",
    );
    f.write(
        "src/theme.ts",
        "export const colors = { primary: '#5599fe' };\n",
    );
    let picked = f.read(&["src/cart.ts", "src/theme.ts"], &["cart", "total"]);
    assert_eq!(
        picked.len(),
        1,
        "a file without the prompt's words is left out"
    );
    assert_eq!(picked[0].path, "src/cart.ts");
    assert_eq!(picked[0].start_line, 1);
    assert!(picked[0].text.contains("cartTotal"));
}

#[test]
fn a_file_that_looks_like_it_holds_a_key_is_never_read_into_a_prompt() {
    let f = fixture(ON);
    // Built at run time so the fixture is not itself a key-shaped line.
    let armour = |edge: &str| format!("-----{edge} RSA {}-----", "PRIVATE KEY");
    f.write(
        "src/cart.ts",
        &format!(
            "// cart signing key\n{}\nMIIEowIBAAKCAQEA1c7b0q2xQ0cartcartcartcartcart\n{}\n",
            armour("BEGIN"),
            armour("END")
        ),
    );
    f.write("src/cart-total.ts", "export const cartTotal = 0;\n");
    let (parts, names) = f.read_named(&["src/cart.ts", "src/cart-total.ts"], &["cart"]);
    assert_eq!(
        parts
            .iter()
            .map(|part| part.path.as_str())
            .collect::<Vec<_>>(),
        ["src/cart-total.ts"]
    );
    assert_eq!(
        names,
        ["src/cart-total.ts"],
        "a refused file is not even named"
    );
}

#[test]
fn a_folder_picked_in_the_dashboard_keeps_to_its_picked_files() {
    let f = fixture(ON);
    f.write("src/cart.ts", "export const cartTotal = 0;\n");
    f.write("src/cart-tax.ts", "export const cartTax = 0;\n");
    picked::save(
        f.home.path(),
        &[picked::Folder {
            workspace: f.root.clone(),
            sources: vec!["src/cart-tax.ts".into()],
            notes_read: false,
            notes_propose: false,
        }],
    )
    .unwrap();
    let paths: Vec<String> = f
        .read(&["src/cart.ts", "src/cart-tax.ts"], &["cart"])
        .into_iter()
        .map(|part| part.path)
        .collect();
    assert_eq!(paths, ["src/cart-tax.ts"]);
}

#[test]
fn nothing_is_read_where_project_context_is_off() {
    let f = fixture("[context_assistance]\nenabled=false\nruntime_id='selected'\n");
    f.write("src/cart.ts", "export const cartTotal = 0;\n");
    assert!(f.read(&["src/cart.ts"], &["cart"]).is_empty());
}

#[test]
fn a_name_that_is_not_an_app_id_reads_nothing() {
    let f = fixture(ON);
    f.write("src/cart.ts", "export const cartTotal = 0;\n");
    let until = Instant::now() + Duration::from_secs(5);
    let found = vec!["src/cart.ts".to_owned()];
    let words = vec!["cart".to_owned()];
    assert!(quick_excerpts(
        f.home.path(),
        &f.root,
        "Claude Code",
        &found,
        &words,
        8,
        until
    )
    .0
    .is_empty());
    assert_eq!(f.read(&["src/cart.ts"], &["cart"]).len(), 1);
}

#[test]
fn reading_stops_at_the_deadline() {
    let f = fixture(ON);
    f.write("src/cart.ts", "export const cartTotal = 0;\n");
    let found = vec!["src/cart.ts".to_owned()];
    let words = vec!["cart".to_owned()];
    let past = Instant::now();
    let (parts, names) = quick_excerpts(
        f.home.path(),
        &f.root,
        "claude-code",
        &found,
        &words,
        8,
        past,
    );
    assert!(parts.is_empty() && names.is_empty());
}
