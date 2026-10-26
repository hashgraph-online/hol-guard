"""Error contract and portable projection for the native Linux kernel boundary."""


class LinuxContainmentUnavailableError(RuntimeError):
    """No repository code may run when the required kernel boundary fails."""


def _socket_filter(machine: str) -> list[tuple[int, int, int, int]]:
    from ..native_restricted_linux import linux_native

    return [tuple(row) for row in linux_native("linux_socket_filter", {"machine": machine}, dict)["instructions"]]
