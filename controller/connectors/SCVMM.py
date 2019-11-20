import logging
import aiohttp
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
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout, sock_read=timeout*4))

    def __del__(self):
        self.session.close()

    async def __send_get_request(self, url: str, payload: dict) -> bool:
        try:
            async with self.session.post(url=url, json=payload) as resp:
                self.logger.info(f"Request to {url}, result: {resp.status}.")
                self.logger.debug(f"Payload: {payload}")
                return 200 <= resp.status < 300
        except Exception as e:
            self.logger.exception(str(e))
            return False

    async def list_vms(self, domain: str, username: str) -> Tuple[VM, ...]:
        url = self.SCVMM_URL + "vm/list"
        params = {
            'domain': domain,
            'username': username
        }

        try:
            async with self.session.get(url=url, params=params) as resp:
                if resp.status >= 300 or resp.status < 200:
                    return ()

                data = await resp.json()

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

    async def start(self, vmid: str) -> bool:
        url = self.SCVMM_URL + "vm/start"
        payload = {'vmid': vmid}
        return await self.__send_get_request(url=url, payload=payload)

    async def shutdown(self, vmid: str) -> bool:
        url = self.SCVMM_URL + "vm/shutdown"
        payload = {'vmid': vmid}
        return await self.__send_get_request(url=url, payload=payload)

    async def poweroff(self, vmid: str) -> bool:
        url = self.SCVMM_URL + "vm/poweroff"
        payload = {'vmid': vmid}
        return await self.__send_get_request(url=url, payload=payload)

    async def save(self, vmid: str) -> bool:
        url = self.SCVMM_URL + "vm/save"
        payload = {'vmid': vmid}
        return await self.__send_get_request(url=url, payload=payload)

    async def list_checkpoints(self, *a, **kw) -> tuple:
        raise NotImplementedError

    async def create_checkpoint(self, *a, **kw) -> bool:
        raise NotImplementedError

    async def remove_checkpoint(self, *a, **kw) -> bool:
        raise NotImplementedError
