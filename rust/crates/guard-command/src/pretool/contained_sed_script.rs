//! Whether a `sed` script only reshapes the text the stage is handed.
//!
//! `sed` is not only a text filter. Its scripts open files and run programs:
//! `r FILE` and `R FILE` read one, `w FILE`, `W FILE` and the `s///w FILE`
//! flag write one, and GNU's `e COMMAND` and the `s///e` flag run a shell.
//! A stage carrying any of those touches something other than the standard
//! input the containment proof screened, so it keeps the command's review.
//! Screening the switches and counting the operands cannot see any of it,
//! because all of it lives inside the script.
//!
//! The same letters are ordinary characters inside an address, a regular
//! expression, a replacement or an appended line, so the reader walks the
//! script far enough to know which letter stands in a function position.
//! Anything it cannot place is refused: a script the reader does not
//! understand is a script the proof cannot describe.

/// Longest script the reader walks. A filter an agent types to cut a block
/// out of a log is far shorter, and a longer one keeps its review rather
/// than being walked.
const MAX_SCRIPT_CHARS: usize = 1024;

/// Whether `script` only reads standard input and writes standard output.
pub(in crate::pretool) fn text_filter_script(script: &str) -> bool {
    if script.len() > MAX_SCRIPT_CHARS {
        return false;
    }
    Reader {
        characters: script.chars().collect(),
        index: 0,
    }
    .walk()
}

/// What stood where an address was allowed to stand.
enum Address {
    /// The command names no address, so a function follows directly.
    Absent,
    /// An address the reader walked to its end.
    Read,
    /// An address the reader could not place.
    Malformed,
}

struct Reader {
    characters: Vec<char>,
    index: usize,
}

impl Reader {
    fn peek(&self) -> Option<char> {
        self.characters.get(self.index).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let character = self.peek();
        if character.is_some() {
            self.index += 1;
        }
        character
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(' ') | Some('\t')) {
            self.index += 1;
        }
    }

    fn digits(&mut self) -> bool {
        let start = self.index;
        while matches!(self.peek(), Some(character) if character.is_ascii_digit()) {
            self.index += 1;
        }
        self.index > start
    }

    /// Every command in the script, each one an optional address range, an
    /// optional negation and one function.
    fn walk(&mut self) -> bool {
        loop {
            while matches!(self.peek(), Some(' ' | '\t' | '\n' | ';')) {
                self.index += 1;
            }
            let Some(character) = self.peek() else {
                return true;
            };
            if character == '#' {
                while !matches!(self.peek(), None | Some('\n')) {
                    self.index += 1;
                }
                continue;
            }
            if character == '}' {
                self.index += 1;
                continue;
            }
            if !self.addresses() {
                return false;
            }
            self.skip_blanks();
            while self.peek() == Some('!') {
                self.index += 1;
                self.skip_blanks();
            }
            let Some(function) = self.bump() else {
                return false;
            };
            if !self.function(function) {
                return false;
            }
        }
    }

    /// One address, or two separated by a comma.
    fn addresses(&mut self) -> bool {
        match self.address() {
            Address::Malformed => return false,
            Address::Absent => return true,
            Address::Read => {}
        }
        self.skip_blanks();
        if self.peek() != Some(',') {
            return true;
        }
        self.index += 1;
        self.skip_blanks();
        // `addr,+N` and `addr,~N` end the range by a count rather than by a
        // line or a pattern.
        if matches!(self.peek(), Some('+') | Some('~')) {
            self.index += 1;
            return self.digits();
        }
        matches!(self.address(), Address::Read)
    }

    fn address(&mut self) -> Address {
        match self.peek() {
            Some(character) if character.is_ascii_digit() => {
                self.digits();
                // `first~step` selects every step-th line from `first`.
                if self.peek() == Some('~') {
                    self.index += 1;
                    if !self.digits() {
                        return Address::Malformed;
                    }
                }
                Address::Read
            }
            Some('$') => {
                self.index += 1;
                Address::Read
            }
            Some('/') => {
                self.index += 1;
                if self.regular_expression('/') {
                    self.address_flags();
                    Address::Read
                } else {
                    Address::Malformed
                }
            }
            // `\cREc` spells the same address with its own delimiter.
            Some('\\') => {
                self.index += 1;
                match self.bump() {
                    Some(delimiter) if self.regular_expression(delimiter) => {
                        self.address_flags();
                        Address::Read
                    }
                    _ => Address::Malformed,
                }
            }
            _ => Address::Absent,
        }
    }

    /// `I` and `M` follow an address's pattern to case-fold it or to read it
    /// across lines.
    fn address_flags(&mut self) {
        while matches!(self.peek(), Some('I') | Some('M')) {
            self.index += 1;
        }
    }

    /// A pattern up to its closing delimiter, with backslash escapes and
    /// bracket expressions read the way the delimiter search has to read
    /// them.
    fn regular_expression(&mut self, delimiter: char) -> bool {
        while let Some(character) = self.bump() {
            match character {
                '\\' => {
                    if self.bump().is_none() {
                        return false;
                    }
                }
                '[' if delimiter != '[' => {
                    if !self.bracket_expression() {
                        return false;
                    }
                }
                character if character == delimiter => return true,
                _ => {}
            }
        }
        false
    }

    /// A `[...]` set, where the delimiter is an ordinary character and a
    /// leading `^` or `]` belongs to the set.
    fn bracket_expression(&mut self) -> bool {
        if self.peek() == Some('^') {
            self.index += 1;
        }
        if self.peek() == Some(']') {
            self.index += 1;
        }
        while let Some(character) = self.bump() {
            if character == ']' {
                return true;
            }
            // `[:alpha:]`, `[.a.]` and `[=a=]` carry their own closing pair.
            if character == '[' && matches!(self.peek(), Some(':' | '.' | '=')) {
                let Some(kind) = self.bump() else {
                    return false;
                };
                loop {
                    match self.bump() {
                        None => return false,
                        Some(character) if character == kind && self.peek() == Some(']') => {
                            self.index += 1;
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        false
    }

    fn function(&mut self, function: char) -> bool {
        match function {
            // `r`/`R` read a file, `w`/`W` write one, GNU `e` runs a shell
            // command and `F` prints the input's name. None of them is the
            // standard input the stage was screened for.
            'r' | 'R' | 'w' | 'W' | 'e' | 'F' => false,
            's' => self.substitute(),
            'y' => self.transliterate(),
            // `a`, `i` and `c` carry their own text, which reaches standard
            // output and nothing else.
            'a' | 'i' | 'c' => {
                self.text_argument();
                true
            }
            'b' | 't' | 'T' | ':' => {
                self.label();
                true
            }
            // A block opens with the next command rather than ending here.
            '{' => true,
            // The rest move text between the pattern and hold spaces, print
            // it, or end the cycle. `l`, `q` and `Q` take a number.
            '=' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'l' | 'n' | 'N' | 'p' | 'P' | 'q' | 'Q'
            | 'x' | 'z' => {
                self.skip_blanks();
                self.digits();
                self.end_of_command()
            }
            _ => false,
        }
    }

    /// Whether what follows a function is the end of that command.
    fn end_of_command(&mut self) -> bool {
        self.skip_blanks();
        matches!(self.peek(), None | Some(';' | '\n' | '}' | '#'))
    }

    /// The text `a`, `i` and `c` append, either on the same line or after a
    /// backslash, up to the first unescaped newline.
    fn text_argument(&mut self) {
        while let Some(character) = self.bump() {
            match character {
                '\\' => {
                    self.bump();
                }
                '\n' => return,
                _ => {}
            }
        }
    }

    /// The label `b`, `t`, `T` and `:` name, up to the end of its command.
    fn label(&mut self) {
        self.skip_blanks();
        while !matches!(self.peek(), None | Some(';' | '\n' | '}')) {
            self.index += 1;
        }
    }

    fn substitute(&mut self) -> bool {
        let Some(delimiter) = self.bump() else {
            return false;
        };
        if matches!(delimiter, '\\' | '\n') {
            return false;
        }
        self.regular_expression(delimiter) && self.replacement(delimiter) && self.substitute_flags()
    }

    fn transliterate(&mut self) -> bool {
        let Some(delimiter) = self.bump() else {
            return false;
        };
        if matches!(delimiter, '\\' | '\n') {
            return false;
        }
        self.replacement(delimiter) && self.replacement(delimiter) && self.end_of_command()
    }

    /// A replacement or a transliteration set, up to its closing delimiter.
    fn replacement(&mut self, delimiter: char) -> bool {
        while let Some(character) = self.bump() {
            match character {
                '\\' => {
                    if self.bump().is_none() {
                        return false;
                    }
                }
                character if character == delimiter => return true,
                _ => {}
            }
        }
        false
    }

    fn substitute_flags(&mut self) -> bool {
        loop {
            match self.peek() {
                Some('g' | 'p' | 'i' | 'I' | 'm' | 'M') => self.index += 1,
                Some(character) if character.is_ascii_digit() => self.index += 1,
                // `w FILE` and `W FILE` write the replaced line to a file,
                // and `e` runs the replacement as a shell command.
                Some('w' | 'W' | 'e') => return false,
                _ => return self.end_of_command(),
            }
        }
    }
}
