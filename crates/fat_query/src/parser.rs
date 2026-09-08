use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Query {
    pub kind: String,
    pub from: String,
    pub to: String,
}

pub fn parse_query(input: &str) -> Result<Query, String> {
    serde_yaml::from_str(input).map_err(|e| format!("invalid query yaml: {e}"))
}
