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
# after this you can run a few aws commands that will use profile_one
imsa assume profile_one
# after this you can run a few aws commands that will use profile_one
imsa assume profile_two
# optional
imsa stop
```

Configuration
-------------

You configure `imsa assume` with a YAML file(see `imsa assume --help`). Each
key in it is a profile that you can assume. If you want, you can provide a
default section for default values like your access key. Otherwise, you might
have to repeat configuration values. Example:

```yaml
```
