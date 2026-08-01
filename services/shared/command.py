import subprocess


def run_command(
    command: list[str],
    timeout: int = 30,
    raise_on_error: bool = False,
) -> subprocess.CompletedProcess:
    """
    Execute a system command and return the result.

    Why check=False by default?
    Security tools often return non-zero exit codes for "no findings"
    (e.g., YARA returns 1 when no rules match). Letting each service
    decide whether a non-zero exit is an error avoids false exceptions.

    Args:
        command:        Command as a list of strings. Never pass a
                        shell string — that is a security risk.
        timeout:        Maximum execution time in seconds.
        raise_on_error: If True, raises CommandError when the command
                        exits with a non-zero return code.

    Returns:
        subprocess.CompletedProcess with .stdout, .stderr, .returncode

    Raises:
        CommandError: If raise_on_error=True and returncode != 0.
        subprocess.TimeoutExpired: If the command exceeds timeout.
    """
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )

    if raise_on_error and result.returncode != 0:
        from shared.exceptions import CommandError
        raise CommandError(
            f"Command failed (exit {result.returncode}): {' '.join(command)}\n"
            f"stderr: {result.stderr.strip()}"
        )

    return result