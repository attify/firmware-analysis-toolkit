use fat_core::debug::DebugSurfaceState;

#[test]
fn debug_surface_states_expose_registered_ready_and_validated() {
    let serialized = [
        serde_json::to_value(DebugSurfaceState::Registered).expect("registered"),
        serde_json::to_value(DebugSurfaceState::Ready).expect("ready"),
        serde_json::to_value(DebugSurfaceState::Validated).expect("validated"),
    ];

    assert_eq!(DebugSurfaceState::Registered.as_str(), "registered");
    assert_eq!(DebugSurfaceState::Ready.as_str(), "ready");
    assert_eq!(DebugSurfaceState::Validated.as_str(), "validated");

    assert_eq!(
        serde_json::from_value::<DebugSurfaceState>(serialized[0].clone()).expect("registered"),
        DebugSurfaceState::Registered
    );
    assert_eq!(
        serde_json::from_value::<DebugSurfaceState>(serialized[1].clone()).expect("ready"),
        DebugSurfaceState::Ready
    );
    assert_eq!(
        serde_json::from_value::<DebugSurfaceState>(serialized[2].clone()).expect("validated"),
        DebugSurfaceState::Validated
    );
}
