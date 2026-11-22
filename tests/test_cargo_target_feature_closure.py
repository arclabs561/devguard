from devguard.sweeps.repo_hygiene import _target_required_features


def test_target_implies_local_features_only() -> None:
    manifest = {
        "features": {
            "default": ["unrelated"],
            "bundle": ["intermediate", "dep:external", "dependency/foreign", "optional?/weak"],
            "intermediate": ["bundle", "inner"],
            "inner": [],
        },
        "example": [{"name": "covered", "required-features": ["bundle"]}],
    }
    assert _target_required_features(manifest, "example", "covered", "examples/covered.rs") == {
        "bundle",
        "intermediate",
        "inner",
    }
    assert not _target_required_features(manifest, "example", "other", "examples/other.rs")
    assert not _target_required_features(manifest, "test", "covered", "tests/covered.rs")


def test_cfg_range_uses_only_structural_braces() -> None:
    from devguard.sweeps.repo_hygiene import _cfg_gated_ranges

    source = [
        '#[cfg(feature = "optional")]',
        "fn gated(value: &'static str) {",
        r'    let bytes = b"before } \" after";',
        '    let raw = br##"embedded " and }',
        '        /* } */ "##;',
        "    let brace = '}'; // }",
        "    /* { /* } */ } */",
        "    crate::optional::run();",
        "}",
        "fn following() { crate::optional::run(); }",
    ]
    assert _cfg_gated_ranges(source) == [(1, 8)]
