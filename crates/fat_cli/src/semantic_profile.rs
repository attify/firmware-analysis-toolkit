use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticProfileMatch {
    pub id: &'static str,
    pub primary_family: &'static str,
    pub matched_terms: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticContext {
    pub profile: Option<SemanticProfileMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateSemantics {
    pub family: &'static str,
    pub score_adjustment: i32,
    pub reasons: Vec<String>,
}

struct SemanticProfile {
    id: &'static str,
    primary_family: &'static str,
    trigger_terms: &'static [&'static str],
}

const SEMANTIC_PROFILES: &[SemanticProfile] = &[
    SemanticProfile {
        id: "homekit",
        primary_family: "Home automation/control",
        trigger_terms: &["homekit", "hm", "hap", "matter", "thread"],
    },
    SemanticProfile {
        id: "continuity",
        primary_family: "Continuity/device relay",
        trigger_terms: &["continuity", "handoff", "nearby", "awdl", "companion"],
    },
];

pub(crate) fn detect_semantic_context(
    binary: &Path,
    linked_libraries: &[String],
    entrypoint_clues: &[String],
) -> SemanticContext {
    let mut corpus = Vec::new();
    corpus.push(binary.display().to_string());
    corpus.extend(linked_libraries.iter().cloned());
    corpus.extend(entrypoint_clues.iter().cloned());

    let mut best: Option<SemanticProfileMatch> = None;
    for profile in SEMANTIC_PROFILES {
        let matched_terms = profile
            .trigger_terms
            .iter()
            .filter(|term| corpus.iter().any(|item| contains_token(item, term)))
            .map(|term| (*term).to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        if matched_terms.is_empty() {
            continue;
        }

        let candidate = SemanticProfileMatch {
            id: profile.id,
            primary_family: profile.primary_family,
            matched_terms,
        };

        if best
            .as_ref()
            .map(|current| current.matched_terms.len() < candidate.matched_terms.len())
            .unwrap_or(true)
        {
            best = Some(candidate);
        }
    }

    SemanticContext { profile: best }
}

pub(crate) fn classify_candidate(
    linked: &str,
    path: &Path,
    context: &SemanticContext,
) -> CandidateSemantics {
    let family = classify_family(linked, path);
    let mut score_adjustment = 0;
    let mut reasons = vec![format!("semantic family: {family}.")];

    if let Some(profile) = &context.profile {
        reasons.push(format!(
            "active semantic profile {} matched terms: {}.",
            profile.id,
            profile.matched_terms.join(", ")
        ));

        if family == profile.primary_family {
            score_adjustment += 90;
            reasons.push(format!(
                "{} aligns with the active primary family {}.",
                path.display(),
                profile.primary_family
            ));
        } else if family == "Apple media runtime" {
            score_adjustment -= 25;
            reasons.push(
                "generic media runtime dependency was down-ranked behind profile-aligned ingress/control components."
                    .to_string(),
            );
        } else if family == "Apple base/system runtime" {
            score_adjustment -= 40;
            reasons.push(
                "generic base/system dependency was down-ranked behind profile-aligned components."
                    .to_string(),
            );
        }
    }

    if linked.contains("PrivateFrameworks") {
        score_adjustment += 10;
        reasons.push("private framework evidence increases specificity.".to_string());
    }

    CandidateSemantics {
        family,
        score_adjustment,
        reasons,
    }
}

pub(crate) fn classify_family(linked: &str, path: &Path) -> &'static str {
    let combined = format!("{} {}", linked, path.display()).to_ascii_lowercase();
    if matches_any(
        &combined,
        &[
            "audiotoolbox",
            "coreaudio",
            "coremedia",
            "mediatoolbox",
            "mediaexperience",
        ],
    ) {
        return "Apple media runtime";
    }
    if matches_any(
        &combined,
        &[
            "foundation",
            "corefoundation",
            "security",
            "systemconfiguration",
            "iokit",
            "coreutils",
            "libsystem",
            "libobjc",
        ],
    ) {
        return "Apple base/system runtime";
    }
    "General linked component"
}

fn contains_token(value: &str, token: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(&token.to_ascii_lowercase())
}

fn matches_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}
