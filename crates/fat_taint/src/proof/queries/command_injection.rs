//! Command injection query — find paths from input to `system`/`popen`/`exec*`.
//!
//! The sinks below are ISO C and POSIX, so they hold wherever they are linked.
//! The *sources* are not: a name like a platform's request-parameter getter
//! carries request data only on the platform that defines it. So the primary
//! catalog compiled in here is limited to specified functions, and everything
//! else is passed in by the caller from an operator-selected profile.
//!
//! Persisted-state sources have no specified members at all — which function
//! reads a device's config store is entirely a per-target claim — so the
//! secondary query analyses nothing until the caller supplies names.

/// Command execution sinks specified by ISO C and POSIX.
const SPECIFIED_SINKS: &[&str] = &["system", "popen", "execl", "execlp", "execv"];

/// Input sources specified by ISO C and by the FastCGI/CGI interface.
const SPECIFIED_PRIMARY_SOURCES: &[&str] = &["getenv", "FCGX_GetParam"];

fn name_list(names: &[String]) -> String {
    names
        .iter()
        .map(|name| serde_json::to_string(name).expect("string serialization cannot fail"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn specified(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

/// The primary source set for a run: the specified functions plus the caller's.
pub fn primary_sources(supplied: &[String]) -> Vec<String> {
    let mut sources = specified(SPECIFIED_PRIMARY_SOURCES);
    for name in supplied {
        if !sources.contains(name) {
            sources.push(name.clone());
        }
    }
    sources
}

/// Joern CPGQL query for primary sources (direct request ingress).
///
/// `supplied` names come from the operator's profile and are added to the
/// specified set.
pub fn primary_query(supplied: &[String]) -> String {
    let sources = name_list(&primary_sources(supplied));
    let sinks = name_list(&specified(SPECIFIED_SINKS));
    format!(
        r#"
println("=== Command Injection: Primary Sources (request ingress) ===")

val httpSources = cpg.call.name({sources})

val cmdSinks = cpg.call.name({sinks})

val flows = cmdSinks.reachableByFlows(httpSources)
flows.p.foreach(println)

println(s"\nTotal primary flows: ${{flows.l.size}}")
"#
    )
}

/// Joern CPGQL query for secondary sources (persisted/shared state).
///
/// With no supplied names the query reports that nothing was analysed rather
/// than silently substituting a guess at the target's config API.
pub fn secondary_query(supplied: &[String]) -> String {
    if supplied.is_empty() {
        return r#"
println("=== Command Injection: Secondary Sources (persisted state) ===")
println("No persisted-state sources were supplied; nothing was analysed.")
println("Pass this target's config-read functions to analyse persisted state.")
"#
        .to_string();
    }

    let sources = name_list(supplied);
    let sinks = name_list(&specified(SPECIFIED_SINKS));
    format!(
        r#"
println("=== Command Injection: Secondary Sources (persisted state) ===")

val persistedSources = cpg.call.name({sources})

val cmdSinks = cpg.call.name({sinks})

val flows = cmdSinks.reachableByFlows(persistedSources)
flows.p.foreach(println)

println(s"\nTotal secondary flows: ${{flows.l.size}}")
"#
    )
}

/// Combined query that runs both source sets and labels the results.
pub fn combined_query(primary_supplied: &[String], secondary_supplied: &[String]) -> String {
    let primary = primary_sources(primary_supplied);
    let sources = name_list(&primary);
    let sinks = name_list(&specified(SPECIFIED_SINKS));

    let mut script = format!(
        r#"
println("=== Command Injection Analysis ===")

val httpSources = cpg.call.name({sources})

val cmdSinks = cpg.call.name({sinks})

println("\n--- Primary (direct request ingress) ---")
val primaryFlows = cmdSinks.reachableByFlows(httpSources)
primaryFlows.p.foreach(println)
println(s"Primary flows: ${{primaryFlows.l.size}}")
"#
    );

    if secondary_supplied.is_empty() {
        script.push_str(
            "\nprintln(\"\\n--- Secondary (persisted state) ---\")\n\
             println(\"No persisted-state sources were supplied; nothing was analysed.\")\n",
        );
    } else {
        let persisted = name_list(secondary_supplied);
        script.push_str(&format!(
            r#"
val persistedSources = cpg.call.name({persisted})

println("\n--- Secondary (persisted state) ---")
val secondaryFlows = cmdSinks.reachableByFlows(persistedSources)
secondaryFlows.p.foreach(println)
println(s"Secondary flows: ${{secondaryFlows.l.size}}")
"#
        ));
    }

    // Callers often want the sink calls themselves, independent of any source
    // model: a non-literal argument to system() is an observation about the
    // code, not a claim about a platform.
    script.push_str(
        r#"
println("\n--- All system() calls with non-literal arguments ---")
cpg.call.name("system").argument.order(1).filterNot(_.isLiteral).code.l.foreach(println)
"#,
    );
    script
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_source_names_remain_string_literals() {
        for name in ["quoted\"name", "back\\slash", "line\nname", "tab\tname"] {
            let encoded = name_list(&[name.to_string()]);
            let decoded: String = serde_json::from_str(&encoded)
                .expect("source name must remain one escaped string literal");
            assert_eq!(decoded, name);
        }
    }

    /// The names the queries used to hard-code. None may appear unless the
    /// caller supplies it.
    const PLATFORM_NAMES: &[&str] = &[
        "CGI_Find_Parameter",
        "cgi_get",
        "web_get",
        "nvram_get",
        "getcfg",
        "Get_Private_Profile_String",
        "GetProfileString",
        "uci_get",
    ];

    #[test]
    fn queries_carry_no_platform_source_names_by_default() {
        let queries = [
            primary_query(&[]),
            secondary_query(&[]),
            combined_query(&[], &[]),
        ];
        for query in queries {
            for name in PLATFORM_NAMES {
                assert!(
                    !query.contains(name),
                    "generated query names the platform function {name}:\n{query}"
                );
            }
        }
    }

    #[test]
    fn the_specified_models_are_still_compiled_in() {
        let query = primary_query(&[]);
        assert!(query.contains("\"getenv\""), "{query}");
        assert!(query.contains("\"FCGX_GetParam\""), "{query}");
        assert!(query.contains("\"system\""), "{query}");
    }

    #[test]
    fn supplied_sources_reach_the_generated_queries() {
        let supplied = vec!["example_get_param".to_string()];
        assert!(primary_query(&supplied).contains("\"example_get_param\""));
        assert!(combined_query(&supplied, &[]).contains("\"example_get_param\""));

        let persisted = vec!["example_store_get".to_string()];
        let secondary = secondary_query(&persisted);
        assert!(secondary.contains("\"example_store_get\""));
        assert!(secondary.contains("reachableByFlows"));
        assert!(combined_query(&[], &persisted).contains("\"example_store_get\""));
    }

    #[test]
    fn an_unsupplied_secondary_query_analyses_nothing_and_says_so() {
        let query = secondary_query(&[]);
        assert!(!query.contains("reachableByFlows"), "{query}");
        assert!(query.contains("nothing was analysed"), "{query}");
    }

    #[test]
    fn a_supplied_name_is_not_duplicated_into_the_specified_set() {
        let sources = primary_sources(&["getenv".to_string()]);
        assert_eq!(sources.iter().filter(|name| *name == "getenv").count(), 1);
    }
}
