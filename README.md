# ansible-aptly

Ansible role to deploy [Aptly](https://www.aptly.info/), the Debian repository
manager, to enable robust patch-management of Debian/Ubuntu hosts and the
locking-down of specific package versions.

This is most helpful in production environments where new hosts must be
deployed with qualified software versions, rather than whatever happens to be
the latest (and only) version present in the upstream repositories at the time.

