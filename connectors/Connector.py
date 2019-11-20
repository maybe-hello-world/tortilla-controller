from abc import ABC, abstractmethod

from typing import Tuple
from data.VM import VM


class Connector(ABC):

    @abstractmethod
    def list_vms(self, domain: str, username: str) -> Tuple[VM, ...]:
        """
        Returns list of available virtual machine
        :param domain: domain of the user
        :param username: username
        :return tuple with
        """
        pass

    @abstractmethod
    def start(self, vmid: str) -> bool:
        """Start a specified virtual machine"""
        pass

    @abstractmethod
    def save(self, vmid: str) -> bool:
        """Save a specified virtual machine"""
        pass

    @abstractmethod
    def shutdown(self, vmid: str) -> bool:
        """Gracefully shutdown a specified virtual machine"""
        pass

    @abstractmethod
    def poweroff(self, vmid: str) -> bool:
        """Forcefully shutdown a specified virtual machine"""
        pass

    @abstractmethod
    def list_checkpoints(self, *a, **kw) -> tuple:
        """List available checkpoints for specified virtual machine"""
        pass

    @abstractmethod
    def create_checkpoint(self, *a, **kw) -> bool:
        """Create checkpoint on specified virtual machine from current state"""
        pass

    @abstractmethod
    def remove_checkpoint(self, *a, **kw) -> bool:
        """Remove specified checkpoint"""
        pass
