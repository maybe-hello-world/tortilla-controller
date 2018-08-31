def list_vms(domain: str, username: str) -> list:
	pass


def start(vmid: str) -> bool:
	pass


def shutdown(vmid: str) -> bool:
	pass


def power_off(vmid: str) -> bool:
	pass


def save(vmid: str) -> bool:
	pass


methods = {
	"list": list_vms
}
