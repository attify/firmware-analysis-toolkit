use crate::android::discovery::{AndroidApkContainerInventory, AndroidArtifactKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AndroidGraphNodeKind {
    Container,
    Artifact,
    Component,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidGraphNode {
    pub id: String,
    pub kind: AndroidGraphNodeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidGraphEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidCapabilityGraphSummary {
    pub node_count: usize,
    pub edge_count: usize,
    pub component_node_count: usize,
    pub artifact_node_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidCapabilityGraph {
    #[serde(default)]
    pub nodes: Vec<AndroidGraphNode>,
    #[serde(default)]
    pub edges: Vec<AndroidGraphEdge>,
    pub summary: AndroidCapabilityGraphSummary,
}

pub fn build_android_capability_graph(
    containers: &[AndroidApkContainerInventory],
) -> AndroidCapabilityGraph {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for container in containers {
        let container_id = format!("container:{}", container.apk_path);
        nodes.push(AndroidGraphNode {
            id: container_id.clone(),
            kind: AndroidGraphNodeKind::Container,
        });

        for artifact in &container.artifacts {
            if matches!(artifact.kind, AndroidArtifactKind::Other) {
                continue;
            }
            let artifact_id = format!("artifact:{}:{}", container.apk_path, artifact.path);
            nodes.push(AndroidGraphNode {
                id: artifact_id.clone(),
                kind: AndroidGraphNodeKind::Artifact,
            });
            edges.push(AndroidGraphEdge {
                from: container_id.clone(),
                to: artifact_id,
                kind: "BundledIn".into(),
            });
        }

        for component in &container.manifest.components {
            let component_id = format!("component:{}:{}", container.apk_path, component.name);
            nodes.push(AndroidGraphNode {
                id: component_id.clone(),
                kind: AndroidGraphNodeKind::Component,
            });
            edges.push(AndroidGraphEdge {
                from: container_id.clone(),
                to: component_id,
                kind: "DeclaredIn".into(),
            });
        }
    }

    let component_node_count = nodes
        .iter()
        .filter(|node| matches!(node.kind, AndroidGraphNodeKind::Component))
        .count();
    let artifact_node_count = nodes
        .iter()
        .filter(|node| matches!(node.kind, AndroidGraphNodeKind::Artifact))
        .count();

    let summary = AndroidCapabilityGraphSummary {
        node_count: nodes.len(),
        edge_count: edges.len(),
        component_node_count,
        artifact_node_count,
    };

    AndroidCapabilityGraph {
        nodes,
        edges,
        summary,
    }
}
