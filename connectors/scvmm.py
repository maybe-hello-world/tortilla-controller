import requests

controller_url = "http://127.0.0.1:5555/api/"


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

		return vm_list

	except (requests.RequestException, KeyError):
		return []


def start(vmid: str) -> bool:
	url = controller_url + "vm/start"
	payload = {'vmid': vmid}
	try:
		resp = requests.post(url, data=payload, timeout=5)
		return resp.status_code == 204
	except requests.RequestException:
		return False


def shutdown(vmid: str) -> bool:
	url = controller_url + "vm/shutdown"
	payload = {'vmid': vmid}
	try:
		resp = requests.post(url, data=payload, timeout=5)
		return resp.status_code == 204
	except requests.RequestException:
		return False


def power_off(vmid: str) -> bool:
	url = controller_url + "vm/poweroff"
	payload = {'vmid': vmid}
	try:
		resp = requests.post(url, data=payload, timeout=5)
		return resp.status_code == 204
	except requests.RequestException:
		return False


def save(vmid: str) -> bool:
	url = controller_url + "vm/save"
	payload = {'vmid': vmid}
	try:
		resp = requests.post(url, data=payload, timeout=5)
		return resp.status_code == 204
	except requests.RequestException:
		return False


methods = {
	"list": list_vms,
	"start": start,
	"shutdown": shutdown,
	"poweroff": power_off,
	"save": save
}
