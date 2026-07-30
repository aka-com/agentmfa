//! Display-safe treatment for agent- and upstream-controlled text.
//!
//! These strings are still data, never trusted instructions. The helper only
//! makes their visible representation honest: it replaces control and format
//! characters which can hide, reorder, or splice what a person sees, while
//! preserving ordinary newlines and tabs used by request previews.

/// Unicode format controls (`General_Category=Cf`) plus invisible filler
/// characters which render as blank despite belonging to another category.
///
/// Kept as ranges instead of a Unicode table dependency so this policy is
/// small, auditable, and shared by every broker/app surface.
fn is_invisible_format(character: char) -> bool {
    matches!(
        character,
        '\u{00AD}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061C}'
            | '\u{06DD}'
            | '\u{070F}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08E2}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{110BD}'
            | '\u{110CD}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// Replace a character which could invisibly change a displayed decision.
pub fn display_char(character: char) -> char {
    if is_invisible_format(character)
        || (character.is_control() && character != '\n' && character != '\t')
    {
        '\u{FFFD}'
    } else {
        character
    }
}

/// Sanitize without changing the visible-text length budget.
pub fn sanitize(text: &str) -> String {
    text.chars().map(display_char).collect()
}

/// Sanitize and cap by Unicode scalar count, adding an ellipsis when capped.
pub fn cap(text: &str, limit: usize) -> String {
    let mut output: String = text.chars().take(limit).map(display_char).collect();
    if text.chars().nth(limit).is_some() {
        output.push('…');
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_controls_and_invisible_fillers_become_visible_replacements() {
        let hostile = [
            '\u{00AD}',
            '\u{061C}',
            '\u{180E}',
            '\u{200B}',
            '\u{200C}',
            '\u{200D}',
            '\u{2060}',
            '\u{2065}',
            '\u{3164}',
            '\u{FEFF}',
            '\u{FFA0}',
            '\u{E0001}',
            '\u{E007F}',
        ]
        .into_iter()
        .collect::<String>();
        assert_eq!(
            sanitize(&hostile),
            std::iter::repeat_n('\u{FFFD}', hostile.chars().count()).collect::<String>()
        );
        assert_eq!(sanitize("line\n\ttext"), "line\n\ttext");
    }

    #[test]
    fn capping_counts_unicode_characters_after_sanitizing() {
        assert_eq!(cap("ab\u{200B}cd", 3), "ab\u{FFFD}…");
        assert_eq!(cap("é", 1), "é");
    }
}
