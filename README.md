PyWeakServices tool
===================

When performing a security testing on a Windows environment, or any environment for that matter, one of the things you’ll need to check is if you can escalate your privileges from a low privilege user to a high privileged user. No matter what environment you are testing there are going to be a range or roles with varying privileges. For the most part, on a local windows environment there going to be three roles / privileged users.

1. System
2. Administrator
3. Regular user

This script search privilege escalation via weak services that are running with administrative privileges.
This script will inspect existing services to look for an non-secure file or configuration permissions that may be hijacked.

#####Examples:

* Invoke the services which the "everyone" group has permissions for.

`python pywakservices.py --everyone`

* Invoke the services which the current user, that is located in certain groups, that have permissions for.

`python pywakservices.py --currentuser`