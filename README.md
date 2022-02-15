IMSA (Instance Metadata Service for Authentication)
===================================================

[![Build Status](https://github.com/sblask/imsa/actions/workflows/build.yml/badge.svg)](https://github.com/sblask/imsa/actions/workflows/build.yml)

If you use **AWS**, you probably know what access keys are. In their basic form
they are very simple to use. However, if you set up MFA or need to assume an
**IAM** role to get something done, it can get complicated. At the very least
it's inconvenient to have to re-enter an MFA token or choose a profile every
time you run a command.

**IMSA** leverages the support for **EC2** instance metadata in AWS cli and
SDKs.  It's a service running in the background that implements the instance
metadata's credentials API and provides commands with temporary credentials.
Once a session is created you won't need to re-enter an MFA token for the
lifetime of the session (usually 12 hours) even if you switch roles. One
drawback of this is that only one role/profile can be active at a time whereas
normally you can provide different profiles whenever you run a command. Also
see the [EC2 documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials).

IMSA is inspired by [Limes](https://github.com/otm/limes) and aims at having a
better architecture, simpler configuration and a lot less code.

Usage
-----

```bash
# check out available options
imsa --help
# as the service run on port 80, sudo is required,
# but you may want to run this on startup anyway (see Installation)
sudo imsa start
# after this you can run a few aws commands that will use profile_ONE
imsa assume profile_ONE
# after this you can run a few aws commands that will use profile_TWO
imsa assume profile_TWO
# if you then want to use profile_ONE in one shell while keep using profile_TWO
# everywhere else, you can use the following which takes advantage of the
# provider chain (see Configuration) by exporting environment variables - it
# still tries to re-use the existing session so you only have to use MFA if
# necessary - it also exports IMSA_PROFILE and IMSA_PROFILE_EXPIRATION which
# you can for example display in your prompt
eval $(imsa export profile_ONE)
# optional - profile_TWO would become unavailable immediately while profile_ONE
# would be available until the credentials expired(check the
# IMSA_PROFILE_EXPIRATION environment variable)
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
loopback device which restricts its availability to your machine (you still
need to be careful with proxies and the like). This can be done in Linux (a way
to make this work in Mac OS is described
[here](https://blog.felipe-alfaro.com/2017/03/22/persistent-loopback-interfaces-in-mac-os-x/))
by editing `/etc/network/interfaces`. Assuming it looks like this:

```text
auto lo
iface lo inet loopback
```

You need to change it to this:

```text
auto lo lo:imsa
iface lo inet loopback

iface lo:imsa inet static
  address 169.254.169.254
  network 169.254.169.254
  netmask 255.255.255.0
```

[This](https://www.aangelis.gr/blog/2016/04/multiple-loopback-ips-in-arch-linux)
might be an alternative, but I did not test it.

If you want to run IMSA at startup you can use the serviced unit file
`imsa.service` (which assumes the above installation path):

```bash
sudo cp imsa.service /etc/systemd/system/
sudo systemctl enable imsa.service
```

If you don't want to reboot your machine to make the IP setup work and IMSA
start up, you can run the following:

```bash
sudo systemctl restart networking.service
sudo systemctl start imsa.service
```

Completions are available through
[argcomplete](https://pypi.org/project/argcomplete/) so you can do:

```bash
eval "$(/opt/imsa/bin/register-python-argcomplete imsa)"
```

to get completions to work for your current shell session or you can pipe the
output of:

```bash
/opt/imsa/bin/register-python-argcomplete imsa
```

into a file that you source from your shell rc file. See
[argcomplete](https://pypi.org/project/argcomplete/) for more details.

Configuration
-------------

IMSA is configured with a YAML file called `.imsa` located in your home
directory. Only `imsa assume` and `imsa export` read this and then forward
configuration as necessary. Given the following example:

```yaml

some_base_profile:
    aws_access_key_id: XXXXXXXXXXXXXXXXXXXX
    aws_secret_access_key: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    role_session_name: SomeSessionName
    mfa_serial_number: arn:aws:iam::XXXXXXXXXXXX:mfa/UserName

profile_one:
    extends: some_base_profile
    role_arn: arn:aws:iam::XXXXXXXXXXXX:role/RoleNameOne

profile_two:
    extends: some_base_profile
    role_session_name: SomeOtherSessionName
    role_arn: arn:aws:iam::XXXXXXXXXXXX:role/RoleNameTwo
```

You can assume `some_base_profile`, `profile_one` and `profile_two`. The latter
two extend `some_base_profile` which means that they use the values from
`some_base_profile` that they don't override. A profile can define any of the
values in the example. No sanity check is done, so you have to get the values
right in **IAM** and then copy them from there.

Note the [provider
chain](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence)
where instance metadata is the last provider in the chain. So all other
providers have to be absent in order for IMSA to work. Conversely, you can for
example provide environment variables to temporarily use different credentials.
