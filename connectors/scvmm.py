import requests
import logging

controller_url = "http://127.0.0.1:5555/api/"
logger = logging.getLogger("scvmm")


def list_vms(domain: str, username: str) -> list:
	url = controller_url + "vm/list"
	params = {
		'domain': domain,
		'username': username
	}

	try:
		resp = requests.get(url, params=params, timeout=5)
		data = resp.json()
		vm_list = []

		for x in data:
			vm_list.append({
				"name": x['Name'],
				"vmid": x['ID'],
				"status": x['VirtualMachineState'],
				"task": x['MostRecentTask'],
				"taskStatus": x['MostRecentTaskUIState'],
				"vmhost": x['VMHost'],
				"protocol": "vmrdp",
				"port": 2179,
				"vmprovider": "scvmm"
			})

		logger.debug("VM list for {}\\{} returned".format(domain, username))
		return vm_list

	except (requests.RequestException, KeyError) as e:
		logger.exception(e)
		return []


def start(vmid: str) -> bool:
	url = controller_url + "vm/start"
	payload = {'vmid': vmid}
	try:
		resp = requests.post(url, data=payload, timeout=5)
		logger.info(str(vmid) + " start request sent, status: " + str(resp.status_code))
		return resp.status_code == 204
	except requests.RequestException as e:
		logger.exception(str(e))
		return False


def shutdown(vmid: str) -> bool:
	url = controller_url + "vm/shutdown"
	payload = {'vmid': vmid}
	try:
		resp = requests.post(url, data=payload, timeout=5)
		logger.info(str(vmid) + " shutdown request sent, status: " + str(resp.status_code))
		return resp.status_code == 204
	except requests.RequestException as e:
		logger.exception(str(e))
		return False


def power_off(vmid: str) -> bool:
	url = controller_url + "vm/poweroff"
	payload = {'vmid': vmid}
	try:
		resp = requests.post(url, data=payload, timeout=5)
		logger.info(str(vmid) + " poweroff request sent, status: " + str(resp.status_code))
		return resp.status_code == 204
	except requests.RequestException as e:
		logger.exception(str(e))
		return False


def save(vmid: str) -> bool:
	url = controller_url + "vm/save"
	payload = {'vmid': vmid}
	try:
		resp = requests.post(url, data=payload, timeout=5)
		logger.info(str(vmid) + " save request sent, status: " + str(resp.status_code))
		return resp.status_code == 204
	except requests.RequestException as e:
		logger.exception(str(e))
		return False


methods = {
	"list": list_vms,
	"start": start,
	"shutdown": shutdown,
	"poweroff": power_off,
	"save": save
}
