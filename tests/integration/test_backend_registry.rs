use std::collections::HashMap;
use std::path::PathBuf;

struct FakeCommandProbe {
    commands: HashMap<String, PathBuf>,
}

impl FakeCommandProbe {
    fn with_commands(entries: &[(&str, &str)]) -> Self {
        Self {
            commands: entries
                .iter()
                .map(|(command, path)| ((*command).to_string(), PathBuf::from(path)))
                .collect(),
        }
    }
}

impl fat_backend::CommandProbe for FakeCommandProbe {
    fn command_path(&self, command: &str) -> Option<PathBuf> {
        self.commands.get(command).cloned()
    }
}

#[test]
fn backend_registry_can_rank_a_family_match() {
    let registry = fat_backend::model::BackendRegistry::with_test_backends();
    let probe = FakeCommandProbe::with_commands(&[("qemu-system-arm", "/usr/bin/qemu-system-arm")]);
    let scores = registry.rank_family_with_probe("linux-router-arm", &probe);
    assert!(!scores.is_empty());
    assert_eq!(scores[0].backend_id, "firmae");
    assert!(!scores[0].availability.is_available);
    assert_eq!(scores[1].backend_id, "firmadyne");
    assert_eq!(scores[2].backend_id, "qemu-direct");
    assert!(scores[2].availability.is_available);
}
