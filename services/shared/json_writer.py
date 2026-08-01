import json
from pathlib import Path


def write_json(path: str, data: dict) -> None:
    """
    Write a Python dictionary to a JSON file.

    Creates parent directories automatically.
    Overwrites the file if it already exists.

    Args:
        path: Destination file path (string or Path).
        data: Dictionary to serialize as JSON.
    """
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4, ensure_ascii=False)


def read_json(path: str) -> dict:
    """
    Read a JSON file and return it as a Python dictionary.

    Why this exists: services need to read output from previous
    pipeline stages. Using a shared reader ensures consistent
    error messages across all services.

    Args:
        path: Path to a JSON file written by another service.

    Returns:
        Parsed dictionary.

    Raises:
        FileNotFoundError: If the file does not exist yet.
        ValueError: If the file exists but is not valid JSON.
    """
    source = Path(path)

    if not source.exists():
        raise FileNotFoundError(
            f"Expected input file not found: {path}\n"
            f"Ensure the previous pipeline stage has completed successfully."
        )

    try:
        with source.open("r", encoding="utf-8") as file:
            return json.load(file)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc