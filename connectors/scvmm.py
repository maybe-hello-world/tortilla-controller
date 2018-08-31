def list_vms(domain: str, username: str) -> list:
	return [
		{
			"name": "guacamole_db",
			"status": "Running",
			"vmid": "123456asd-321dasd-kjbsdf1-11",
			"task": "Save state of virtual machine",
			"taskstatus": "Failed",
			"vmhost": "hv2.avalon.ru",
			"protocol": "vmrdp",
			"port": 3389,
			"vmprovider": "scvmm"
		}
	]


def start(vmid: str) -> bool:
	return True


def shutdown(vmid: str) -> bool:
	return False


def power_off(vmid: str) -> bool:
	return False


def save(vmid: str) -> bool:
	return False


methods = {
	"list": list_vms,
	"start": start,
	"shutdown": shutdown
}
