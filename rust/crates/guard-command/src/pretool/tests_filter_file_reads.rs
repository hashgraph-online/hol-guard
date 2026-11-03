use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

fn allowed(command: &str) -> bool {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    evaluate_pre_tool_with_context(&request(command), Some(root), Some(root))
        .is_ok_and(|decision| decision.minimum_action == "allow")
}

#[test]
fn a_filter_reading_a_proven_file_needs_no_review() {
    for command in [
        "sort Cargo.toml",
        "sort -u Cargo.toml",
        "sort -rn Cargo.toml",
        "sort Cargo.toml src/pretool.rs",
        "uniq Cargo.toml",
        "uniq -c Cargo.toml",
        "cut -d= -f1 Cargo.toml",
        "cut -c1-10 Cargo.toml",
        // `-k` and `-t` carry a key definition and a field separator, not a
        // second file to read, attached or as the next word.
        "sort -k2 Cargo.toml",
        "sort -k 2,2 Cargo.toml",
        "sort -t= -k2 Cargo.toml",
        "sort -t = -k 1 Cargo.toml",
        "sort -nk2 Cargo.toml",
        "sort --key=2 --field-separator== Cargo.toml",
        "sort -z -c Cargo.toml",
        "sort -S 16M Cargo.toml",
        // The shell writes `$'\\t'` out before Guard reads the word, so a tab
        // separator arrives as the character itself and is screened as the
        // one literal it is.
        "sort -t$'\\t' -k2 -n Cargo.toml",
        "sort --field-separator=$'\\t' --key=2 Cargo.toml",
        "cut -d$'\\t' -f1 Cargo.toml",
        // `paste`, `join` and `column` lay out the columns of what they read.
        // Their value-taking options carry a delimiter, a field number or a
        // width, so none of them names a file to write.
        "paste Cargo.toml Cargo.toml",
        "paste -d$'\\t' Cargo.toml Cargo.toml",
        "paste -s -d, Cargo.toml",
        "paste --delimiters=$'\\t' Cargo.toml",
        "join Cargo.toml Cargo.toml",
        "join -t$'\\t' -1 2 -2 2 Cargo.toml Cargo.toml",
        "join -a 1 -o auto Cargo.toml Cargo.toml",
        "column -t Cargo.toml",
        "column -t -s$'\\t' Cargo.toml",
        "column -t -s, -o ' | ' Cargo.toml",
        // `nl`, `tac`, `rev`, `fold`, `expand`, `unexpand`, `fmt` and `comm`
        // number, reverse, wrap, retab, reflow or compare the lines of what
        // they read, and their value-taking options carry a separator, a
        // width, a prefix or a set of tab stops.
        "nl Cargo.toml",
        "nl -ba -w2 Cargo.toml",
        "nl -s$'\\t' Cargo.toml",
        "nl --number-separator=$'\\t' --number-width=3 Cargo.toml",
        "tac Cargo.toml",
        "tac -s$'\\t' Cargo.toml",
        "tac -r -s '^#' Cargo.toml",
        "rev Cargo.toml",
        "fold -w 40 Cargo.toml",
        "fold -s -w40 Cargo.toml",
        "expand -t4 Cargo.toml",
        "unexpand -a -t 4 Cargo.toml",
        "fmt -w 72 Cargo.toml",
        "fmt -72 Cargo.toml",
        "fmt -p '# ' -s Cargo.toml",
        "comm -12 Cargo.toml Cargo.toml",
        "comm --output-delimiter=, Cargo.toml Cargo.toml",
        // `strings`, `hexdump`, `xxd`, `pr`, `shuf`, `iconv` and the base
        // encoders print a rendering of what they read. Their value-taking
        // options carry a length, an offset, a radix, a page geometry or a
        // character set.
        "strings Cargo.toml",
        "strings -n 6 Cargo.toml",
        "strings -a -t x Cargo.toml",
        "hexdump -C Cargo.toml",
        "hexdump -n 64 -s 16 Cargo.toml",
        "xxd Cargo.toml",
        "xxd -l 64 -c 16 Cargo.toml",
        "xxd -p -g 1 Cargo.toml",
        "pr -t Cargo.toml",
        "pr -t -w 72 -l 60 Cargo.toml",
        "pr -3 Cargo.toml",
        "shuf -n 3 Cargo.toml",
        "shuf --head-count=3 Cargo.toml",
        "iconv -f utf-8 -t ascii Cargo.toml",
        "iconv --from-code=utf-8 --to-code=ascii -c Cargo.toml",
        "base32 Cargo.toml",
        "base64 Cargo.toml",
        "base64 -d Cargo.toml",
        "base64 -w 76 Cargo.toml",
        "base64 --wrap=0 Cargo.toml",
        "base32 -w 0 Cargo.toml",
    ] {
        assert!(allowed(command), "{command}");
    }
}

#[test]
fn a_filter_that_could_write_or_reach_further_still_takes_review() {
    for command in [
        // `-o` names an output file.
        "sort -o sorted.txt Cargo.toml",
        // `uniq INPUT OUTPUT` truncates the second operand.
        "uniq Cargo.toml counted.txt",
        // No selection, so `cut` was never proven.
        "cut Cargo.toml",
        // `tr` takes character sets, never a file.
        "tr a-z A-Z Cargo.toml",
        // An operand outside the proven read scope.
        "sort /nonexistent-guard-fixture/secret.key",
        "cut -d: -f1 /nonexistent-guard-fixture/passwd",
        // `-T` names a directory for the temporary runs and
        // `--compress-program` hands them to another program.
        "sort -T /tmp Cargo.toml",
        "sort --compress-program=gzip Cargo.toml",
        // `--output` is `-o` spelled long, and an abbreviation of it is not a
        // reading option either.
        "sort --output=sorted.txt Cargo.toml",
        "sort --out=sorted.txt Cargo.toml",
        // A separator is still one literal character: a parameter is a
        // reference the shell has not written out, and two tabs are not a
        // delimiter.
        "sort -t$SEPARATOR -k2 Cargo.toml",
        "cut -d$'\\t\\t' -f1 Cargo.toml",
        "cut -d$DELIMITER -f1 Cargo.toml",
        // The new filters reach no further than the operands they are proven
        // for: `join` pairs exactly two inputs, and an option none of these
        // screens has read keeps the command under review.
        "paste -d$'\\t' /nonexistent-guard-fixture/secret.key Cargo.toml",
        "join Cargo.toml Cargo.toml Cargo.toml",
        "join -t$SEPARATOR Cargo.toml Cargo.toml",
        "column -t -s$'\\t' --json Cargo.toml",
        "paste --output-delimiter=x Cargo.toml",
        // The layout filters reach no further either: `comm` compares exactly
        // two inputs, an unread option keeps the command under review, and a
        // parameter is still a reference the shell has not written out.
        "nl -s$'\\t' /nonexistent-guard-fixture/secret.key",
        "comm -12 Cargo.toml Cargo.toml Cargo.toml",
        "tac -s$SEPARATOR Cargo.toml",
        "fmt --output=wrapped.txt Cargo.toml",
        "fold --write=40 Cargo.toml",
        // The dump filters write nothing only while the writing spellings
        // stay out: `xxd INPUT OUTPUT` truncates its second operand, `shuf`
        // and `iconv` spell an output file, `hexdump -f` reads a format file
        // Guard has not proven, and `base64 -o` names a file to write. A
        // line-wrap flag that carries no count swallows the operand instead,
        // so nothing is proven read.
        "xxd Cargo.toml dumped.hex",
        "shuf -o shuffled.txt Cargo.toml",
        "shuf --output=shuffled.txt Cargo.toml",
        "shuf --random-source=Cargo.toml Cargo.toml",
        "iconv -o converted.txt -f utf-8 -t ascii Cargo.toml",
        "iconv --output=converted.txt Cargo.toml",
        "hexdump -f format.txt Cargo.toml",
        "base32 -o encoded.txt Cargo.toml",
        "base32 --output=encoded.txt Cargo.toml",
        "base64 -w notanumber Cargo.toml",
        "base64 -b Cargo.toml",
        // An operand outside the proven read scope, an option none of these
        // screens has read, and a parameter the shell has not written out.
        "strings /nonexistent-guard-fixture/secret.key",
        "xxd /nonexistent-guard-fixture/secret.key",
        "pr --unknown Cargo.toml",
        "strings -t $RADIX Cargo.toml",
        // `pr -s` carries an attached separator or none, so the word after a
        // bare `-s` is a file `pr` opens; `xxd` reads `-ps` whole as its own
        // spelling of `-p`, so the word after it is an operand too, and the
        // second operand is the file `xxd` would truncate. Reading either as
        // a flag that swallows the next word would leave an unproven path
        // out of the proof.
        "pr -s /tmp/secret.key Cargo.toml",
        "printf x | pr -s /tmp/secret.key",
        "xxd -ps /tmp/secret.key Cargo.toml",
        // GNU `strings` reads a leading `@` operand as a file of further
        // arguments, so the names it opens are not in this command line.
        "strings @args.txt",
    ] {
        assert!(!allowed(command), "{command}");
    }
}

fn allowed_without_context(command: &str) -> bool {
    evaluate_pre_tool_with_context(&request(command), None, None)
        .is_ok_and(|decision| decision.minimum_action == "allow")
}

/// A file operand is opened, so it takes `cat`'s read proof, and that proof
/// only holds against a verified home and working directory. With neither,
/// the screen reads the spelling alone, which cannot tell a plain name from a
/// link to a secret. The stdin forms carry no operand and stay proven.
#[test]
fn a_filter_reading_a_file_without_a_verified_context_takes_review() {
    for command in [
        "sort Cargo.toml",
        "uniq Cargo.toml",
        "cut -d= -f1 Cargo.toml",
        "paste Cargo.toml Cargo.toml",
        "join Cargo.toml Cargo.toml",
        "column -t Cargo.toml",
        "nl Cargo.toml",
        "tac Cargo.toml",
        "rev Cargo.toml",
        "fold -w 40 Cargo.toml",
        "expand Cargo.toml",
        "unexpand Cargo.toml",
        "fmt Cargo.toml",
        "comm -12 Cargo.toml Cargo.toml",
        "strings Cargo.toml",
        "hexdump -C Cargo.toml",
        "xxd Cargo.toml",
        "pr -t Cargo.toml",
        "shuf -n 3 Cargo.toml",
        "iconv -f utf-8 -t ascii Cargo.toml",
    ] {
        assert!(!allowed_without_context(command), "{command}");
    }
}
