//! SPEC-03 T-28 (REQ-28, C260): the code-comment scans of the relay.
//!
//! The relay comment fixes of SPEC-03 §11.1 ship with relay release R-A1,
//! before the client release that brings the rest of T-28's scans
//! (`desktop/frontend/src/__tests__/voice-docs.test.ts`). These tests keep
//! the corrected comments from regressing:
//!
//! - `server/src/handlers.rs` and `server/src/models.rs` contain neither
//!   "cannot decrypt" nor "cannot interpret";
//! - the doc comments of `VoiceKeyExchange` and `SrtpVoicePacket` do not
//!   contain "SRTP" as a word.

use std::path::PathBuf;

/// Reads a file of this crate, relative to `server/`.
fn read_crate_file(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// The text of a Rust source with comment markers and line breaks removed,
/// lowercased, and with every run of whitespace collapsed to one space, so
/// that a phrase wrapped across comment lines is still found.
fn normalized(source: &str) -> String {
    let joined = source
        .lines()
        .map(|line| {
            line.trim_start()
                .trim_start_matches("///")
                .trim_start_matches("//!")
                .trim_start_matches("//")
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    joined.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether `text` contains `word` with no letter, digit or underscore
/// directly before or after it (a regex `\bword\b`, case-sensitive).
fn contains_word(text: &str, word: &str) -> bool {
    let is_word_char = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(word).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + word.len()..].chars().next();
        !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char)
    })
}

/// The doc comments of the enum variant that opens with the line
/// `<variant> {`: the `///` block directly above it (attributes between
/// are skipped) and the `///` lines of its fields.
fn variant_doc_comments(source: &str, variant: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let opening = format!("{variant} {{");
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.trim() == opening)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        starts.len(),
        1,
        "expected exactly one line `{opening}` in models.rs, found {}",
        starts.len()
    );
    let start = starts[0];

    let mut above = Vec::new();
    for line in lines[..start].iter().rev() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("///") {
            above.push(trimmed);
        } else if trimmed.starts_with("#[") {
            continue;
        } else {
            break;
        }
    }
    assert!(
        !above.is_empty(),
        "`{variant}` has no doc comment in models.rs"
    );
    above.reverse();

    let fields = lines[start + 1..]
        .iter()
        .map(|line| line.trim_start())
        .take_while(|line| *line != "}," && *line != "}")
        .filter(|line| line.starts_with("///"));

    above
        .into_iter()
        .chain(fields)
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn t28_relay_sources_make_no_cannot_decrypt_claim() {
    for rel in ["src/handlers.rs", "src/models.rs"] {
        let text = normalized(&read_crate_file(rel));
        for phrase in ["cannot decrypt", "cannot interpret"] {
            assert!(
                !text.contains(phrase),
                "server/{rel} contains \"{phrase}\" (SPEC-03 REQ-28, C260)"
            );
        }
    }
}

#[test]
fn t28_voice_message_doc_comments_do_not_say_srtp() {
    let models = read_crate_file("src/models.rs");
    for variant in ["VoiceKeyExchange", "SrtpVoicePacket"] {
        let docs = variant_doc_comments(&models, variant);
        assert!(
            !contains_word(&docs, "SRTP"),
            "the doc comments of `{variant}` contain \"SRTP\" as a word \
             (SPEC-03 REQ-28, C260):\n{docs}"
        );
    }
}

#[test]
fn t28_scan_helpers_find_what_they_must() {
    // The scans above pass on the current sources; these cases show that
    // they would fail if the old claims came back.
    assert!(normalized("// the server\n    // CANNOT\n// decrypt it").contains("cannot decrypt"));
    assert!(contains_word("/// SRTP voice key exchange", "SRTP"));
    assert!(contains_word("/// keyed by DTLS-SRTP.", "SRTP"));
    assert!(!contains_word("`SrtpVoicePacket`", "SRTP"));
    assert!(!contains_word("SRTP_FRAME", "SRTP"));

    let source = "\
enum E {
    /// SRTP voice key exchange (opaque to server)
    #[serde(rename = \"x\")]
    VoiceKeyExchange {
        /// a field
        wrapped_key: String,
    },
    /// Other
    Other {},
}
";
    let docs = variant_doc_comments(source, "VoiceKeyExchange");
    assert!(contains_word(&docs, "SRTP"));
    assert!(docs.contains("a field"));
    assert!(!docs.contains("Other"));
}
