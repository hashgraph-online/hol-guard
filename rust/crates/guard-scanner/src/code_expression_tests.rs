use crate::scan_text;
use guard_rules::MAX_SCAN_BYTES;

fn flagged(text: &str) -> bool {
    scan_text(text, true, true, MAX_SCAN_BYTES, None)
        .matches
        .iter()
        .any(|matched| matched.classifier == "credential-assignment")
}

#[test]
fn click_tracking_redirect_route_is_not_a_credential() {
    let route = "\
import { NextResponse } from 'next/server';
import { z } from 'zod';

const querySchema = z.object({
  token: z.string().min(1),
  target: z.string().url(),
});

export async function GET(request: Request) {
  const query = new URL(request.url).searchParams;
  const parsed = querySchema.safeParse({
    token: query.get('token') ?? '',
    target: query.get('target') ?? '',
  });
  if (!parsed.success) {
    return NextResponse.redirect(new URL('/', request.url));
  }
  const token = parsed.data.token;
  await recordClick({ token: token.slice(0, 8), target: parsed.data.target });
  return NextResponse.redirect(parsed.data.target);
}
";
    assert!(!flagged(route));
}

#[test]
fn reminder_worker_that_builds_unsubscribe_links_is_not_a_credential() {
    let worker = "\
type CreateUnsubscribeToken = (params: { userId: string; scope: 'weekly-reminder' }) => Promise<string>;

const isCreateUnsubscribeToken = (value: unknown): value is CreateUnsubscribeToken =>
  typeof value === 'function';

export async function sendReminders(users: User[]) {
  const createUnsubscribeToken = await loadCreateUnsubscribeToken();
  for (const user of users) {
    const unsubscribeToken = await createUnsubscribeToken({
      userId: user.id,
      scope: 'weekly-reminder',
    });
    const unsubscribeUrl = `${baseUrl}/unsubscribe?token=${encodeURIComponent(unsubscribeToken)}`;
    const confirmUrl = `${baseUrl}/confirm?token=${unsubscribeToken}&scope=reminder`;
    await send(user.email, renderReminder({ unsubscribeUrl, confirmUrl }));
  }
}
";
    assert!(!flagged(worker));
}

#[test]
fn reminder_worker_with_multiline_function_type_is_not_a_credential() {
    let worker = "\
type CreateUnsubscribeToken = (params: {
  userId: string;
  scope: 'weekly-reminder';
}) => Promise<string>;
";
    assert!(!flagged(worker));
}

#[test]
fn signing_helper_that_names_environment_secrets_is_not_a_credential() {
    let helper = "\
import { createHmac, timingSafeEqual } from 'crypto';

export function signDeliveryToken(payload: string): string {
  const secret = process.env.DELIVERY_TOKEN_SECRET ?? '';
  const payloadB64 = Buffer.from(payload).toString('base64url');
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  const token = `${payloadB64}.${signature}`;
  return token;
}

export function verifyDeliveryToken(token: string, expected: string): boolean {
  if (token === expected) {
    return true;
  }
  if (token == null) {
    logger.warn('Delivery token HMAC verification failed', { token: token.slice(0, 20) });
  }
  return timingSafeEqual(Buffer.from(token), Buffer.from(expected));
}
";
    assert!(!flagged(helper));
}

#[test]
fn token_handling_in_other_styles_is_not_a_credential() {
    for text in [
        "const token = crypto.randomBytes(32).toString('hex');",
        "const token = await signToken(user.id);",
        "const apiKey = await getApiKey();",
        "const token = req.query.token as string;",
        "const apiKey = req.headers['x-api-key'] as string;",
        "const token = authHeader?.split(' ')[1];",
        "const token = authHeader.replace('Bearer ', '');",
        "const emailToken = jwt.sign({ sub: user.id }, secret);",
        "const token = sign({ id }, secret, { expiresIn: '1h' });",
        "const password = await bcrypt.hash(input, 10);",
        "const auth = { token: await getToken(), user };",
        "href: `${base}/confirm?token=${tok}`,",
        "export const config = { secret: process.env.SECRET!, token: undefined };",
        "tokens.map(token => token.trim())",
        "if (!token || token === expected) {",
        "token = secrets.token_urlsafe(32)",
        "token := generateToken(user)",
        "let token = Uuid::new_v4().to_string();",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn literal_secrets_beside_code_are_still_credentials() {
    let live = ["sk-", "live-abcdefghijklmnop1234"].concat();
    let sample = ["a1b2c3d4", "e5f6g7h8i9j0"].concat();
    let long = ["abcdef123456", "abcdef123456"].concat();
    let hex = ["abcdef0123", "456789abcdef"].concat();
    let run = ["abcdefghijklmnop", "1234567890"].concat();
    for text in [
        "const token = login(user, 'hunter2prod');".to_string(),
        "const token = sign(payload, 'my secret key here');".to_string(),
        "const token = Buffer.from('c2VjcmV0', 'base64');".to_string(),
        "password = getPassword() || correcthorsebatterystaple".to_string(),
        "if (password === expected || 'hunter2' === input) {".to_string(),
        "'password' => 'hunter2',".to_string(),
        r#"password => "S3cretPw9""#.to_string(),
        format!("token = sign({}, 'hunter2prod');", "a".repeat(700)),
        "const token = process.env.TOKEN || 'dev-token-123';".to_string(),
        "const secret = process.env.SECRET ?? 'fallbackSecretValue1';".to_string(),
        "const token = prefix + 'hunter2';".to_string(),
        format!("const token = getKey() + '{long}';"),
        format!("const secret = await vault.read('{long}');"),
        format!("const apiKey = loadKey('{live}');"),
        format!("const token = login(user, '{sample}');"),
        "const token = login(user, 'correct-horse-battery-staple');".to_string(),
        format!("const token = `{live}${{suffix}}`;"),
        format!("const token = `{run}`;"),
        "const password = `correct horse battery staple`;".to_string(),
        "if (password === 'hunter2production') {".to_string(),
        "if (password == 123456) {".to_string(),
        "password=$(echo hunter2)".to_string(),
        "secret = hunter2 || fallback".to_string(),
        "password = hunter2".to_string(),
        "password: foo.bar.baz".to_string(),
        "const secret = 'x' as string;".to_string(),
        format!("token: {hex}"),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
}

#[test]
fn environment_defaults_are_credentials_and_lookups_stay_inert() {
    let secret = ["hunter2", "-production", "-value"].concat();
    for text in [
        format!("TOKEN = os.getenv(\"TOKEN\", \"{secret}\")"),
        format!("token = os.environ.get(\"TOKEN\", \"{secret}\")"),
        format!("let token = std::env::var(\"TOKEN\").unwrap_or(\"{secret}\".into());"),
        format!("const token = Deno.env.get(\"TOKEN\") ?? \"{secret}\";"),
        format!("api_key = ENV.fetch(\"API_KEY\", \"{secret}\")"),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
    for text in [
        "TOKEN = os.getenv(\"TOKEN\")",
        "token = os.environ.get(\"TOKEN\", \"\")",
        "let token = std::env::var(\"TOKEN\").unwrap_or_default();",
        "const token = query.get('token') ?? '';",
        "const token = client.get('token', 'header');",
        "const token = jwt.sign(payload, signingKey, { algorithm: 'HS256' });",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn hash_pairs_with_literal_values_are_credentials() {
    let phrase = ["correct horse", " battery staple"].concat();
    for text in [
        "'password' => 'hunter2'".to_string(),
        "\"password\" => \"S3cretPw9\"".to_string(),
        "password => \"S3cretPw9\"".to_string(),
        ":password => 'hunter2'".to_string(),
        format!("$c = ['db_password' => '{phrase}'];"),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
    for text in [
        "tokens.map(token => token.trim())",
        "const parse = token => token.trim();",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn an_expression_longer_than_the_cursor_reads_is_never_code() {
    let phrase = ["correct-horse", "-battery-staple"].concat();
    let arguments = "user, ".repeat(110);
    let long = format!("const token = sign({arguments}'{phrase}');");
    assert!(long.len() > 600);
    assert!(flagged(&long));
    let short = format!("const token = sign({}'{phrase}');", "user, ".repeat(2));
    assert!(flagged(&short));
}

#[test]
fn interpolated_templates_that_spell_a_passphrase_are_credentials() {
    let hyphenated = ["correct-horse", "-battery-staple"].concat();
    let spoken = ["correct horse", " battery staple "].concat();
    for text in [
        format!("const token = `{hyphenated}${{suffix}}`;"),
        format!("const token = `{spoken}${{suffix}}`;"),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
    for text in [
        "const token = `${base}/reset-password/${id}`;",
        "const token = `Bearer ${raw}`;",
        "const token = `${head}.${sig}`;",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn later_comparison_literals_with_a_value_shape_are_credentials() {
    for text in [
        "if (password === expected || 'hunter2' === input) {",
        "if (password === expected && input === 'hunter2') {",
        "if (password == expected || input == \"S3cretPw9\") {",
    ] {
        assert!(flagged(text), "{text:?}");
    }
    for text in [
        "if (token === expected || scheme === 'Bearer') {",
        "if (password === expected && mode !== 'prod') {",
        "if (token === expected && kind !== '') {",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn long_bare_fallbacks_are_credentials_and_variables_stay_inert() {
    for text in [
        "const password = getPassword(user, 12) || correcthorsebatterystaple;",
        "const token = getToken(user, 12) ?? correcthorsebatterystaple;",
        "const password = getPassword() || correcthorsebatterystaple;",
        "token = getToken() ?? correcthorsebatterystaple",
    ] {
        assert!(flagged(text), "{text:?}");
    }
    for text in [
        "const token = getToken(user, 12) || fallbackToken;",
        "const token = getToken(user, 12) ?? defaults.token;",
        "const token = getToken(user, 12) || fallback_token;",
        "const token = getToken(user, 12) || undefined;",
        "const token = getToken() || fallbackToken;",
        "const token = getToken() ?? defaults.token;",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn short_secrets_passed_to_calls_are_credentials() {
    for text in [
        "const password = login(user, 'hunter2prod');",
        "const token = sign(payload, 'my secret key here');",
        "const token = Buffer.from('c2VjcmV0', 'base64');",
        "const token = sign(payload, 'S3cretPw9');",
    ] {
        assert!(flagged(text), "{text:?}");
    }
    for text in [
        "const token = sign(payload, 'HS256');",
        "const token = Buffer.from(payload).toString('base64url');",
        "const token = header.split(' ').pop();",
        "const token = crypto.createHash('sha256').update(id).digest('hex');",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn defaults_handed_to_getters_and_closures_are_credentials() {
    let secret = ["hunter2", "-production", "-value"].concat();
    for text in [
        format!(
            "let token = std::env::var(\"TOKEN\").unwrap_or_else(|_| \"{secret}\".to_string());"
        ),
        format!("token = os.getenv(\"TOKEN\", default=\"{secret}\")"),
        format!("let token = std::env::var(\"TOKEN\").unwrap_or(String::from(\"{secret}\"));"),
        format!("token = config.get(\"api_token\", \"{secret}\")"),
        format!("const token = settings.get('TOKEN', '{secret}');"),
        format!("token = os.environ.setdefault(\"TOKEN\", \"{secret}\")"),
        format!("let token = maybe.unwrap_or(\"{secret}\");"),
        format!("const token = settings.get(TOKEN_KEY, '{secret}');"),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
    for text in [
        "const token = client.get('token', 'header');",
        "token = os.environ.get(\"TOKEN\", \"\")",
        "let token = std::env::var(\"TOKEN\").unwrap_or_else(|_| String::new());",
        "let token = maybe.unwrap_or(\"none\");",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn request_options_are_not_a_getter_default() {
    for text in [
        "const token = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}});",
        "const token = axios.get(url, {params: {grant_type: 'client_credentials'}});",
        "const tokenResponse = await axios.get('/oauth/token', { params: { grant_type: 'client_credentials' } });",
    ] {
        assert!(!flagged(text), "{text:?}");
    }
}

#[test]
fn a_template_default_holds_no_more_than_a_quoted_one() {
    let secret = ["hunter2", "-production", "-value"].concat();
    for text in [
        format!("const token = settings.get('TOKEN', `{secret}`);"),
        format!("const token = maybe.unwrap_or(`{secret}`);"),
    ] {
        assert!(flagged(&text), "{text:?}");
    }
    assert!(!flagged("const token = settings.get('TOKEN', `none`);"));
}
