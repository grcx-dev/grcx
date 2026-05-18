# Tests for framework YAML files in grcx/controls/frameworks/
import pathlib

import pytest
import yaml

FRAMEWORKS_DIR = pathlib.Path(__file__).parent.parent / "grcx" / "controls" / "frameworks"
REPO_ROOT = pathlib.Path(__file__).parent.parent

framework_paths = sorted(FRAMEWORKS_DIR.glob("*.yaml"))
framework_ids = [p.stem for p in framework_paths]


@pytest.mark.parametrize("path", framework_paths, ids=framework_ids)
def test_framework_loads(path):
    data = yaml.safe_load(path.read_text())
    assert isinstance(data, dict)


@pytest.mark.parametrize("path", framework_paths, ids=framework_ids)
def test_framework_has_required_top_level_keys(path):
    data = yaml.safe_load(path.read_text())
    assert data.get("id"), "Missing or empty 'id'"
    assert data.get("name"), "Missing or empty 'name'"
    controls = data.get("controls")
    assert isinstance(controls, list) and len(controls) > 0, "'controls' must be a non-empty list"


@pytest.mark.parametrize("path", framework_paths, ids=framework_ids)
def test_framework_id_matches_filename(path):
    data = yaml.safe_load(path.read_text())
    assert data["id"] == path.stem, (
        f"Framework id '{data['id']}' does not match filename stem '{path.stem}'"
    )


@pytest.mark.parametrize("path", framework_paths, ids=framework_ids)
def test_framework_controls_have_required_keys(path):
    data = yaml.safe_load(path.read_text())
    for i, control in enumerate(data["controls"]):
        assert control.get("id"), f"Control at index {i} is missing a non-empty 'id'"
        assert control.get("description"), f"Control '{control.get('id', i)}' is missing a non-empty 'description'"
        if "category" in control:
            assert isinstance(control["category"], str) and control["category"].strip(), (
                f"Control '{control['id']}' has an empty 'category'"
            )


@pytest.mark.parametrize("path", framework_paths, ids=framework_ids)
def test_framework_control_ids_unique(path):
    data = yaml.safe_load(path.read_text())
    ids = [c["id"] for c in data["controls"]]
    seen = set()
    duplicates = []
    for cid in ids:
        if cid in seen:
            duplicates.append(cid)
        seen.add(cid)
    assert not duplicates, f"Duplicate control ids found: {duplicates}"


def test_all_frameworks_referenced_in_default_config_exist():
    config_path = REPO_ROOT / "grcx.yaml"
    config = yaml.safe_load(config_path.read_text())
    referenced = config.get("controls", {}).get("frameworks", [])
    assert referenced, "No frameworks listed in grcx.yaml controls.frameworks"
    for framework_id in referenced:
        expected_path = FRAMEWORKS_DIR / f"{framework_id}.yaml"
        assert expected_path.exists(), (
            f"Framework '{framework_id}' is listed in grcx.yaml but "
            f"{expected_path} does not exist"
        )
