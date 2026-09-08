use crate::model::{FamilyEvidence, FamilyGuess, FamilyTraits};

const FAMILY_TRAITS: &[FamilyTraits] = &[
    FamilyTraits {
        family_id: "linux-router-arm",
        labels: &["linux", "router", "arm"],
        signals: &[
            ("arch:armel", 0.35),
            ("arch:arm", 0.35),
            ("fs:squashfs", 0.15),
            ("init:busybox", 0.20),
            ("web:cgi", 0.15),
            ("nvram:present", 0.25),
        ],
    },
    FamilyTraits {
        family_id: "linux-router-mips",
        labels: &["linux", "router", "mips"],
        signals: &[
            ("arch:mips", 0.35),
            ("arch:mipsel", 0.35),
            ("fs:squashfs", 0.15),
            ("init:busybox", 0.20),
            ("web:cgi", 0.15),
            ("nvram:present", 0.25),
        ],
    },
    FamilyTraits {
        family_id: "linux-camera-mips",
        labels: &["linux", "camera", "mips"],
        signals: &[
            ("arch:mips", 0.30),
            ("fs:squashfs", 0.20),
            ("init:busybox", 0.10),
            ("web:cgi", 0.15),
            ("video:onvif", 0.30),
        ],
    },
    FamilyTraits {
        family_id: "linux-camera-ai-mips",
        labels: &["linux", "camera", "ai", "mips", "magik"],
        signals: &[
            ("arch:mips", 0.25),
            ("fs:squashfs", 0.15),
            ("init:busybox", 0.10),
            ("ai_format:magik", 0.25),
            ("ai_lib:jzdl", 0.15),
            ("ai_lib:venus", 0.15),
            ("ai_embed:mk_h", 0.10),
        ],
    },
    FamilyTraits {
        family_id: "mcu-ai-tflite",
        labels: &["mcu", "ai", "tflite", "esp32"],
        signals: &[
            ("ai_format:tflite", 0.30),
            ("ai_lib:tflitemicro", 0.20),
            ("ai_embed:c_array", 0.25),
            ("ai_lib:esp-nn", 0.15),
            ("arch:xtensa", 0.10),
        ],
    },
    FamilyTraits {
        family_id: "linux-camera-ai-tflite",
        labels: &["linux", "camera", "ai", "tflite"],
        signals: &[
            ("ai_format:tflite", 0.30),
            ("ai_lib:edgetpu", 0.15),
            ("ai_lib:coral", 0.15),
            ("fs:squashfs", 0.10),
            ("init:busybox", 0.10),
        ],
    },
    FamilyTraits {
        family_id: "linux-edge-ai-onnx",
        labels: &["linux", "edge", "ai", "onnx"],
        signals: &[
            ("ai_format:onnx", 0.35),
            ("ai_lib:onnxruntime", 0.20),
            ("ai_lib:openvino", 0.15),
            ("ai_lib:tensorrt", 0.15),
            ("ai_lib:vitis_ai", 0.10),
            ("arch:arm64", 0.10),
            ("fs:squashfs", 0.10),
        ],
    },
    FamilyTraits {
        family_id: "qualcomm-edge-ai-dlc",
        labels: &["qualcomm", "edge", "ai", "dlc", "qnn"],
        signals: &[
            ("ai_format:dlc", 0.35),
            ("ai_lib:snpe", 0.20),
            ("ai_lib:qnn", 0.20),
            ("ai_lib:hexagon", 0.15),
            ("ai_lib:hta", 0.10),
            ("arch:arm64", 0.10),
        ],
    },
    FamilyTraits {
        family_id: "linux-gateway-arm64",
        labels: &["linux", "gateway", "arm64"],
        signals: &[
            ("arch:arm64", 0.45),
            ("fs:squashfs", 0.15),
            ("init:busybox", 0.10),
            ("web:cgi", 0.10),
            ("service:dhcp", 0.20),
        ],
    },
    FamilyTraits {
        family_id: "linux-java-appliance",
        labels: &["linux", "java", "appliance"],
        signals: &[
            ("vm:java", 0.40),
            ("service:tomcat", 0.30),
            ("fs:squashfs", 0.10),
            ("web:jsp", 0.25),
        ],
    },
    FamilyTraits {
        family_id: "linux-medical-appliance-arm",
        labels: &["linux", "medical", "arm"],
        signals: &[
            ("arch:arm", 0.30),
            ("fs:squashfs", 0.15),
            ("init:busybox", 0.10),
            ("service:serial", 0.20),
            ("device:medical", 0.40),
        ],
    },
];

pub fn classify_for_test(signals: Vec<&str>) -> FamilyGuess {
    classify(signals)
}

pub fn classify<I, S>(signals: I) -> FamilyGuess
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let normalized_signals: Vec<String> = signals
        .into_iter()
        .map(|signal| signal.as_ref().trim().to_ascii_lowercase())
        .collect();

    let mut best_family_id = "unknown";
    let mut best_score = 0.0_f32;
    let mut best_max_score = 0.0_f32;
    let mut best_evidence = Vec::new();

    for traits in FAMILY_TRAITS {
        let (score, max_score, evidence) = score_family(traits, &normalized_signals);
        if score > best_score {
            best_family_id = traits.family_id;
            best_score = score;
            best_max_score = max_score;
            best_evidence = evidence;
        }
    }

    let confidence = if best_max_score > 0.0 {
        (best_score / best_max_score).clamp(0.0, 1.0)
    } else {
        0.0
    };

    FamilyGuess {
        family_id: best_family_id.to_string(),
        confidence,
        evidence: best_evidence,
    }
}

fn score_family(traits: &FamilyTraits, signals: &[String]) -> (f32, f32, Vec<FamilyEvidence>) {
    let mut score = 0.0_f32;
    let mut evidence = Vec::new();
    let mut max_score = 0.0_f32;

    for &(signal, weight) in traits.signals {
        max_score += weight;
        if signals.iter().any(|candidate| candidate == signal) {
            score += weight;
            evidence.push(FamilyEvidence {
                signal: signal.to_string(),
                weight,
            });
        }
    }

    (score, max_score, evidence)
}
