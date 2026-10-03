"""Package-level smoke tests."""

import automatic_dataset_generation


def test_package_import() -> None:
    assert automatic_dataset_generation.__name__ == "automatic_dataset_generation"
