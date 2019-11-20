from abc import ABC, abstractmethod

from typing import Tuple
from controller.data.VM import VM


class Connector(ABC):

    @abstractmethod
    async def list_vms(self, domain: str, username: str) -> Tuple[VM, ...]:
        """
        Returns list of available virtual machine
        :param domain: domain of the user
        :param username: username
        :return tuple with
        """
        pass

    @abstractmethod
    async def start(self, vmid: str) -> bool:
        """Start a specified virtual machine"""
        pass

    @abstractmethod
    async def save(self, vmid: str) -> bool:
        """Save a specified virtual machine"""
        pass

    @abstractmethod
    async def shutdown(self, vmid: str) -> bool:
        """Gracefully shutdown a specified virtual machine"""
        pass

    @abstractmethod
    async def poweroff(self, vmid: str) -> bool:
        """Forcefully shutdown a specified virtual machine"""
        pass

    @abstractmethod
    async def list_checkpoints(self, *a, **kw) -> tuple:
        """List available checkpoints for specified virtual machine"""
        pass

    @abstractmethod
    async def create_checkpoint(self, *a, **kw) -> bool:
        """Create checkpoint on specified virtual machine from current state"""
        pass

    @abstractmethod
    async def remove_checkpoint(self, *a, **kw) -> bool:
        """Remove specified checkpoint"""
        pass
