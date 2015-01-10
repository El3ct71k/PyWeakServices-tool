import os
import wmi
import win32net
from subprocess import check_output
from argparse import ArgumentParser

# Get user permissions
HOSTNAME = os.environ.get("ComputerName")
USERNAME = os.environ.get("USERNAME")
GROUPS = [groups for groups in win32net.NetUserGetLocalGroups(HOSTNAME, USERNAME)]


def get_services():
	"""
		This function is responsible to get the information of the service list from WMI database.
		Example:
			get_services()
		Result:
			Object with the services.
	"""
	obj_wmi_service = wmi.GetObject(r"winmgmts:\root\cimv2")
	col_items = obj_wmi_service.ExecQuery("SELECT * FROM Win32_Service")
	for items in col_items:
		if items.StartMode != "Disabled":
			if os.path.exists(items.PathName):
				yield items


def search_in_groups(group_name):
	"""
		This function is responsible to check if a specific group is found on the local group list
		Example:
			search_in_groups("Administrators"):
		Result:
			True
		:type group_name: str
		:param group_name: Group for search
	"""
	for group in GROUPS:
		if group in group_name:
			return True
	return False


def service_filter(per_output, current_user, everyone):
	"""
		This function is responsible for filtering the permissions of a services list via local groups
		which the "current user" group permissions or "everyone" permissions group are found on it.
		Example:
			permissions_output = ['NT AUTHORITY\\SYSTEM:(I)(F)', 'BUILTIN\\Administrators:(I)(F)', 'BUILTIN\\Users:(I)(RX)']
			service_filter(permissions_output, True, False)
		Result:
			"Vulnerable :)" because the user got full permissions of this service.
		:type per_output: list
		:param per_output: This list contains the user permissions that see on the service file

		:type current_user: bool
		:param current_user: This variable contains boolean if the filtering is performed via group permissions of current user.

		:type everyone: bool
		:param everyone: This variable contains boolean if the filtering is performed via everyone group permissions
	"""
	for permission in per_output:
		if (current_user and search_in_groups(permission)) or (everyone and str(permission).find("Everyone") > -1):
			status = "Vulnerable :)" if str(permission).find("(F)") > -1 else "Not vulnerable"
			return "{permission}\r\nStatus: {status}".format(permission=permission, status=status)
	return False


def get_details(items, current_user, everyone):
	"""
		This function is responsible to get information of specific services that return the services` details
		after the filtering procedure and parsing it.
		Example:
			get_details(items, False, True)
		Result:
			Service Name: Update service
			Location: C:\Program Files (x86)\example\Updater.exe
			Start Name: LocalSystem
			Start Mode: Auto
			State: Running
			Permissions:
			Everyone:(R,W)
			Status: Not vulnerable

		:type items: object
		:param items: This object contains the service details including full path, name, permissions, etc.

		:type current_user: bool
		:param current_user: This variable contains boolean if the filtering is performed via group permissions of current user.

		:type everyone: bool
		:param everyone: This variable contains boolean if the filtering is performed via everyone group permissions

	"""
	per = check_output(['icacls.exe', items.PathName])
	per_output = [per.strip() for per in per[len(items.PathName):].splitlines()[:-2]]
	user_permission = service_filter(per_output, current_user, everyone)
	if user_permission:
		print "Service Name: {service}\r\n" \
				"Location: {loc}\r\n" \
				"Start Name: {start}\r\n" \
				"Start Mode: {mode}\r\n" \
				"State: {state}\r\nPermissions:\r\n" \
				"{userp}\r\n".format(service=items.Name, loc=items.PathName, start=items.StartName,
									mode=items.StartMode, state=items.State, userp=user_permission)


def main(current_user, everyone):
	"""
		This function is responsible to inform of general information including hostname, username, local / domain groups and services.

		:type current_user: bool
		:param current_user: This variable contains boolean if the filtering is performed via group permissions of current user.

		:type everyone: bool
		:param everyone: This variable contains boolean if the filtering is performed via everyone group permissions
	"""
	if os.environ.get("OS") == 'Windows_NT':

		print "Hostname: {host}\r\nUsername: {user}\r\nGroups: {groups}\r\n".format(host=HOSTNAME, user=USERNAME, groups=", ".join(GROUPS))
		for services in get_services():
			get_details(services, current_user, everyone)
	else:
		print "Not supported."


if __name__ == '__main__':
	parser = ArgumentParser(prog=os.path.basename(__file__), description="PyWeakServices tool")
	parser.add_argument('--current_user', help="show a services when have an permissions to current user", action="store_true")
	parser.add_argument('--everyone', help="show a services when have an permissions to everyone", action="store_true")
	args = vars(parser.parse_args())
	if args['everyone'] or args['current_user']:
		main(**args)
	else:
		parser.print_help()