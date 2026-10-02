//! Constant numeric expressions have no file, network, import or process effects.

struct Expression<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Expression<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn expression(&mut self, depth: usize) -> bool {
        if !self.term(depth) {
            return false;
        }
        loop {
            self.whitespace();
            if !matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
                return true;
            }
            self.position += 1;
            if !self.term(depth) {
                return false;
            }
        }
    }

    fn term(&mut self, depth: usize) -> bool {
        if !self.atom(depth) {
            return false;
        }
        loop {
            self.whitespace();
            if !matches!(self.bytes.get(self.position), Some(b'*' | b'/' | b'%')) {
                return true;
            }
            self.position += 1;
            if !self.atom(depth) {
                return false;
            }
        }
    }

    fn atom(&mut self, depth: usize) -> bool {
        self.whitespace();
        if depth >= 8 {
            return false;
        }
        if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
            self.position += 1;
            return self.atom(depth + 1);
        }
        if self.bytes.get(self.position) == Some(&b'(') {
            self.position += 1;
            if !self.expression(depth + 1) {
                return false;
            }
            self.whitespace();
            if self.bytes.get(self.position) != Some(&b')') {
                return false;
            }
            self.position += 1;
            return true;
        }
        let start = self.position;
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_digit)
        {
            self.position += 1;
        }
        (1..=9).contains(&(self.position - start))
    }
}

pub(super) fn safe_inline_expression(executable: &str, arguments: &[String]) -> bool {
    let [flag, script] = arguments else {
        return false;
    };
    let (flag_expected, prefix) = if matches!(executable, "python" | "python3") {
        ("-c", "print(")
    } else {
        ("-e", "console.log(")
    };
    if flag != flag_expected || script.len() > 256 {
        return false;
    }
    let Some(source) = script
        .trim()
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(')'))
    else {
        return false;
    };
    let mut parser = Expression {
        bytes: source.as_bytes(),
        position: 0,
    };
    if !parser.expression(0) {
        return false;
    }
    parser.whitespace();
    parser.position == parser.bytes.len()
}
