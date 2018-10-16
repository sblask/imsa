IMSA (Instance Metadata Service for Authentication)
===================================================

If you use **AWS**, you probably know what access keys are. In their basic form
they are very simple to use. However, if you set up MFA or need to assume an
**IAM** role to get something done, it can get complicated. At the very least
it's inconvenient to have to re-enter an MFA token or choose a profile every
time you run a command.

**IMSA** leverages the support for **EC2** instance metadata in AWS cli and
SDKs.  It's a service running in the background that implements the instance
metadata's credentials API and provides commands with temporary credentials.
Once a session is created you won't need to re-enter an MFA token for the
lifetime of the session(usually 12 hours) even if you switch roles. One
drawback of this is that only one role/profile can be active at a time whereas
normally you can provide different profiles whenever you run a command. Also
see the [EC2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials).

Usage
-----

```bash
# check out available options
imsa --help
# as the service run on port 80, sudo is required,
# but you may want to run this on startup anyway(see Installation)
sudo imsa start
# after this you can run a few aws commands that will use profile_ONE
imsa assume profile_ONE
# after this you can run a few aws commands that will use profile_TWO
imsa assume profile_TWO
# optional
imsa stop
```

Installation
------------

Being a Python package, you can install IMSA using pip. I would recommend
installing it into a virtualenv:

```bash
sudo virtualenv /opt/imsa
sudo /opt/imsa/bin/pip install git+https://github.com/sblask/imsa.git
sudo ln -s /opt/imsa/bin/imsa /usr/bin

```

The instance metadata service in EC2 is available at 169.254.169.254. So you
need to get your machine to listen at 169.254.169.254 too. As you do not want
to expose your AWS credentials to the outside, you need to add the IP to your
loopback device which restricts its availability to your machine(you still need
to be careful with proxies and the like). This can be done by editing
`/etc/network/interfaces`. Assuming it looks like this:

```
auto lo
iface lo inet loopback
```

You need to change it to this:

```
auto lo lo:imsa
iface lo inet loopback

iface lo:imsa inet static
  address 169.254.169.254
  network 169.254.169.254
  netmask 255.255.255.0
```

If you want to run IMSA at startup you can use the serviced unit file
`imsa.service`(which assumes the above installation path):

```
sudo cp imsa.service /etc/systemd/system/
sudo systemctl enable imsa.service
```

If you don't want to reboot your machine to make the IP setup work and IMSA
start up, you can run the following:

```
sudo systemctl restart networking.service
sudo systemctl start imsa.service
```

Configuration
-------------

IMSA is configured with a YAML file called `.imsa` located in your home
directory. Only `imsa assume` reads this and then forwards configuration as
necessary. Given the following example:

```yaml

default:
    aws_access_key_id: XXXXXXXXXXXXXXXXXXXX
    aws_secret_access_key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    role_session_name: SomeSessionName
    mfa_serial_number: arn:aws:iam::XXXXXXXXXXXX:mfa/UserName
    region_name: eu-west-1

profile_one:
    role_arn: arn:aws:iam::XXXXXXXXXXXX:role/RoleNameOne

profile_two:
    role_arn: arn:aws:iam::XXXXXXXXXXXX:role/RoleNameTwo
```

you can assume `default`, `profile_one` and `profile_two`. The latter two use
the values from `default` which is required. A profile can define any of the
values in the example which will then override the ones from `default`. No
sanity check is done, so you have to get the values right in **IAM** and then
copy them from there.

Note the [provider chain](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#config-settings-and-precedence)
where instance metadata is the last provider in the chain. So all other
providers have to be absent in order for IMSA to work.  Conversely, you can for
example provide environment variables to temporarily use different credentials.
