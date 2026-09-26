use crate::{EntryContent, MimeType, SensitiveReason};

/// MIME type that KDE-compatible password managers (such as `KeePassXC`) offer
/// on Linux to mark a copy as a secret.
const KDE_PASSWORD_MANAGER_HINT: &str = "x-kde-passwordManagerHint";

/// Pasteboard type that password managers offer on macOS to mark a copy as
/// concealed, following the nspasteboard.org convention.
const MACOS_CONCEALED_TYPE: &str = "org.nspasteboard.ConcealedType";

/// Decides whether a clipboard item looks like a secret.
///
/// Each implementation checks one kind of evidence, such as the text itself or
/// the MIME types the source application offered. Scanners run before a
/// [`ClipEntry`](crate::ClipEntry) is built, so they receive the raw parts
/// rather than a finished entry.
///
/// The trait is dyn-compatible, so different scanners can be stored together
/// as `Box<dyn SensitivityScanner>`. It requires `Send + Sync` so that one
/// scanner can be shared between the daemon's threads.
pub trait SensitivityScanner: Send + Sync {
    /// Scans one clipboard item for signs that it is sensitive.
    ///
    /// `content` is the copied content, and `mime_types` are the MIME types the
    /// source application offered for it.
    ///
    /// Returns `Some` with the [`SensitiveReason`] if this scanner finds
    /// evidence of a secret. Returns `None` if it finds nothing. `None` means
    /// "no evidence found by this scanner", not "the content is safe".
    fn scan(&self, content: &EntryContent, mime_types: &[MimeType]) -> Option<SensitiveReason>;
}

/// Flags content that the source application explicitly marked as secret.
///
/// Password managers offer an extra MIME type alongside the copied text to
/// signal a secret, for example `x-kde-passwordManagerHint` on Linux or
/// `org.nspasteboard.ConcealedType` on macOS. If any offered MIME type is one
/// of the known hints, the content is reported as [`SensitiveReason::MimeHint`]
/// carrying the hint that matched.
///
/// Only the presence of a hint type is checked. The data offered under it
/// (usually the word `secret`) is not read.
///
/// [`MimeHintScanner::default`] checks both the Linux and the macOS hint on
/// every platform. The strings never appear on the other platform, so checking
/// both costs nothing and keeps behaviour identical everywhere.
pub struct MimeHintScanner {
    hints: Vec<MimeType>,
}

impl MimeHintScanner {
    /// Creates a scanner that treats any of `hints` as a secret marker.
    #[must_use]
    pub const fn new(hints: Vec<MimeType>) -> Self {
        Self { hints }
    }
}

impl Default for MimeHintScanner {
    /// Creates a scanner for the known Linux and macOS password-manager hints.
    fn default() -> Self {
        Self::new(vec![
            KDE_PASSWORD_MANAGER_HINT.into(),
            MACOS_CONCEALED_TYPE.into(),
        ])
    }
}

/// Flags text that matches a known secret pattern, such as an API token or a
/// private key header.
///
/// Reports [`SensitiveReason::PatternMatch`]. Image and binary content is not
/// scanned.
pub struct PatternScanner {}

/// Runs several scanners in order and returns the first match.
///
/// Scanners are asked one at a time. As soon as one returns `Some`, the rest
/// are skipped, so put the most reliable and cheapest scanners first. Returns
/// `None` if no scanner finds anything.
pub struct ScannerChain {
    scanners: Vec<Box<dyn SensitivityScanner>>,
}

impl ScannerChain {
    /// Creates a chain that asks `scanners` in the given order.
    ///
    /// An empty list is allowed; such a chain never reports anything.
    #[must_use]
    pub const fn new(scanners: Vec<Box<dyn SensitivityScanner>>) -> Self {
        Self { scanners }
    }
}

impl SensitivityScanner for ScannerChain {
    fn scan(&self, content: &EntryContent, mime_types: &[MimeType]) -> Option<SensitiveReason> {
        self.scanners
            .iter()
            .find_map(|scanner| scanner.scan(content, mime_types))
    }
}

impl SensitivityScanner for MimeHintScanner {
    fn scan(&self, _content: &EntryContent, mime_types: &[MimeType]) -> Option<SensitiveReason> {
        mime_types
            .iter()
            .find(|offered| self.hints.contains(offered))
            .cloned()
            .map(SensitiveReason::MimeHint)
    }
}

impl SensitivityScanner for PatternScanner {
    fn scan(&self, content: &EntryContent, mime_types: &[MimeType]) -> Option<SensitiveReason> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake scanner that always gives the same answer.
    struct Fixed(Option<SensitiveReason>);

    impl SensitivityScanner for Fixed {
        fn scan(
            &self,
            _content: &EntryContent,
            _mime_types: &[MimeType],
        ) -> Option<SensitiveReason> {
            self.0.clone()
        }
    }

    /// A fake scanner that fails the test if it is ever asked.
    struct MustNotRun;

    impl SensitivityScanner for MustNotRun {
        fn scan(
            &self,
            _content: &EntryContent,
            _mime_types: &[MimeType],
        ) -> Option<SensitiveReason> {
            panic!("the chain should have stopped before this scanner");
        }
    }

    fn text() -> EntryContent {
        EntryContent::Text("hello".into())
    }

    #[test]
    fn chain_returns_first_match_and_stops() {
        let scanners: Vec<Box<dyn SensitivityScanner>> = vec![
            Box::new(Fixed(None)),
            Box::new(Fixed(Some(SensitiveReason::UserForced))),
            Box::new(MustNotRun),
        ];
        let chain = ScannerChain::new(scanners);

        assert_eq!(chain.scan(&text(), &[]), Some(SensitiveReason::UserForced));
    }

    #[test]
    fn chain_without_matches_returns_none() {
        let scanners: Vec<Box<dyn SensitivityScanner>> =
            vec![Box::new(Fixed(None)), Box::new(Fixed(None))];
        let chain = ScannerChain::new(scanners);

        assert_eq!(chain.scan(&text(), &[]), None);
    }

    #[test]
    fn mime_hint_detects_kde_hint() {
        let offered: Vec<MimeType> = vec!["text/plain".into(), KDE_PASSWORD_MANAGER_HINT.into()];

        let reason = MimeHintScanner::default().scan(&text(), &offered);

        assert_eq!(
            reason,
            Some(SensitiveReason::MimeHint(KDE_PASSWORD_MANAGER_HINT.into()))
        );
    }

    #[test]
    fn mime_hint_detects_macos_concealed_type() {
        let offered: Vec<MimeType> =
            vec!["public.utf8-plain-text".into(), MACOS_CONCEALED_TYPE.into()];

        let reason = MimeHintScanner::default().scan(&text(), &offered);

        assert_eq!(
            reason,
            Some(SensitiveReason::MimeHint(MACOS_CONCEALED_TYPE.into()))
        );
    }

    #[test]
    fn mime_hint_ignores_ordinary_copy() {
        let offered: Vec<MimeType> = vec!["text/plain".into(), "text/html".into()];

        assert_eq!(MimeHintScanner::default().scan(&text(), &offered), None);
    }

    #[test]
    fn mime_hint_uses_custom_hints() {
        let scanner = MimeHintScanner::new(vec!["x-custom-secret".into()]);
        let offered: Vec<MimeType> = vec!["x-custom-secret".into()];

        assert_eq!(
            scanner.scan(&text(), &offered),
            Some(SensitiveReason::MimeHint("x-custom-secret".into()))
        );
        assert_eq!(
            MimeHintScanner::default().scan(&text(), &offered),
            None,
            "custom hints must not leak into the defaults"
        );
    }

    #[test]
    fn empty_chain_returns_none() {
        let chain = ScannerChain::new(Vec::new());

        assert_eq!(chain.scan(&text(), &[]), None);
    }
}
