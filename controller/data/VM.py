from dataclasses import dataclass


@dataclass(frozen=True)
class VM:
    name: str
    vmid: str
    status: str
    task: str
    taskStatus: str
    vmhost: str
    protocol: str
    port: int
    vmprovider: str
