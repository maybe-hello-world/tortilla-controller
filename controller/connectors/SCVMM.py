import logging
import requests
from typing import Tuple

from controller.data.VM import VM
from controller.connectors.Connector import Connector


class SCVMMConnector(Connector):
    def __init__(self, url: str, timeout: int = 30):
        """
        Instatiate SCVMMConnector class

        :param url: url of a SCVMM host
        :param timeout: timeout for all requests
        """

        self.SCVMM_URL = url
        self.logger = logging.getLogger("scvmm")
        self.logger.info("SCVMM API url is set to " + self.SCVMM_URL)
        self.timeout = timeout

    def __send_get_request(self, url: str, payload: dict) -> bool:
        try:
            resp = requests.post(url, data=payload, timeout=self.timeout)
            self.logger.info(f"Request to {url}, result: {resp.status_code}.")
            self.logger.debug(f"Payload: {payload}")
            return 200 <= resp.status_code < 300
        except Exception as e:
            self.logger.exception(str(e))
            return False

    def list_vms(self, domain: str, username: str) -> Tuple[VM, ...]:
        url = self.SCVMM_URL + "vm/list"
        params = {
            'domain': domain,
            'username': username
        }

        try:
            resp = requests.get(url, params=params, timeout=self.timeout)
            if resp.status_code >= 300 or resp.status_code < 200:
                return ()

            data = resp.json()
            vm_list = tuple(
                VM(
                    name=x.get('Name', "-"),
                    vmid=x.get('ID', "-"),
                    status=x.get('VirtualMachineState', "-"),
                    task=x.get('MostRecentTask', "-"),
                    taskStatus=x.get('MostRecentTaskUIState', "-"),
                    vmhost=x.get('VMHost', "-"),
                    protocol="vmrdp",
                    port=2179,
                    vmprovider="scvmm"
                )
                for x in data
            )

            self.logger.debug(f"VM list for {domain}\\{username} returned")
            return vm_list

        except Exception as e:
            self.logger.exception(e)
            return ()

    def start(self, vmid: str) -> bool:
        url = self.SCVMM_URL + "vm/start"
        payload = {'vmid': vmid}
        return self.__send_get_request(url=url, payload=payload)

    def shutdown(self, vmid: str) -> bool:
        url = self.SCVMM_URL + "vm/shutdown"
        payload = {'vmid': vmid}
        return self.__send_get_request(url=url, payload=payload)

    def poweroff(self, vmid: str) -> bool:
        url = self.SCVMM_URL + "vm/poweroff"
        payload = {'vmid': vmid}
        return self.__send_get_request(url=url, payload=payload)

    def save(self, vmid: str) -> bool:
        url = self.SCVMM_URL + "vm/save"
        payload = {'vmid': vmid}
        return self.__send_get_request(url=url, payload=payload)

    def list_checkpoints(self, *a, **kw) -> tuple:
        raise NotImplementedError

    def create_checkpoint(self, *a, **kw) -> bool:
        raise NotImplementedError

    def remove_checkpoint(self, *a, **kw) -> bool:
        raise NotImplementedError
