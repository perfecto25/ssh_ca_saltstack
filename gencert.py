#!/usr/bin/python3

import sys
import os
from os.path import basename
import argparse
import textwrap
import subprocess
import smtplib
import socket
import pathlib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from email.mime.text import MIMEText
import requests
import json
import yaml

base_dir = "/srv/utils/ssh_ca"
mailhost = "your_mail_hostname"
from_email = "SSH_cert_authority@company.com"
admin_email = "admin@company.com"
default_span = "12w"  # 12 week default

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent(
        """
    Gencert
    > ./gencert.py create --name jsmith --type user --span 24h    # generate new keypair + cert for human user jsmith, 24 hour lifespan (will email user w keys + cert)
    > ./gencert.py create --name svc1 --type account   # generate new keypair + cert for service account, no expiration
    > ./gencert.py create -n web1 -t host  # generate new keypair + cert for a host, no expiration
    > ./gencert.py regen -n jsmith -t user  # regenerate cert only (will email the user w new cert)
    > ./gencert.py remove -n jsmith -t user  # removes all keys and certs for user
    > ./gencert.py revoke -n jsmith -t user  # adds user's pub key to revoked_keys file
    > ./gencert.py expiration  # checks human certs for upcoming expiration, if close to expiring, will regen new cert and email new cert to the user

    """
    ),
)
parser.add_argument("action", choices=["create", "regen", "remove", "revoke", "expiration"], type=str,
                    help="create new keypair and cert, revoke existing cert, regenerate new cert based on \
    existing keypair, remove all certs and keys for user, check cert expiration")
parser.add_argument("-n", "--name", help="name of user or host", type=str, required=False)
parser.add_argument("-t", "--type", choices=["user", "host", "account"], type=str,
                    required=False, help="human user, service account or host")
parser.add_argument("-s", "--span", help="certificate lifetime span, ie --span 6w [m=min, h=hours, d=days, w=weeks, y=years]",
                    type=str, required=False, default=default_span)


def send_email(to_addr, from_addr, cc=None, bcc=None, subject=None, body=None, files=None):
    if not to_addr or not from_addr:
        raise Exception("error sending email, To or From values are null")

    # convert TO into list if string
    if type(to_addr) is not list:
        to_addr = to_addr.split()

    to_list = to_addr + [cc] + [bcc]
    to_list = [i for i in to_list if i]  # remove null emails

    msg = MIMEMultipart()
    msg["From"] = from_addr
    msg["Subject"] = subject
    msg["To"] = ",".join(to_addr)
    msg["Cc"] = cc
    msg["Bcc"] = bcc

    msg.attach(MIMEText(body, "html"))

    for file in files or []:
        with open(file, "rb") as f:
            part = MIMEApplication(f.read(), Name=basename(file))

        # After the file is closed
        part['Content-Disposition'] = f"attachment; filename={basename(file)}"
        msg.attach(part)

    try:
        server = smtplib.SMTP(mailhost)
    except smtplib.SMTPAuthenticationError as e:
        raise Exception(f"Error authenticating to SMTP server: {str(e)}, exiting..,")
    except socket.timeout:
        raise Exception("SMTP login timeout")

    try:
        server.sendmail(from_addr, to_list, msg.as_string())
    except smtplib.SMTPException as e:
        raise Exception(str(e))
    finally:
        server.quit()


def errorcheck(func):
    """ catch all exceptions """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"{func} has an exception: \n\n{str(e)}\n")
            send_email(admin_email, from_email, None, None, "SSH CA ERROR", f"{args}, {func} >> {str(e)}")
            slack(str(e))
            sys.exit()
    return wrapper


def slack(error_msg):
    webhook = "https://hooks.slack.com/services/xxxxxxxxxx"
    slackdata = {"text": f"SSH CA error:\n\n {error_msg}"}
    # {json.dumps(errors, sort_keys=False, indent=4)}"
    response = requests.post(
        webhook, data=json.dumps(slackdata), headers={"Content-Type": "application/json"}
    )
    if response.status_code != 200:
        raise ValueError(
            "Request to slack returned an error %s, the response is:\n%s" % (response.status_code, response.text)
        )


def remove_duplicates(filename):
    """ remove duplicate lines from file """
    with open(filename) as fl:
        content = fl.read().split('\n')
    content = set([line for line in content if line != ''])
    content = '\n'.join(content)
    with open(filename, 'w') as fl:
        fl.writelines(content)


@errorcheck
def gen_cert(args):
    """ generate new cert for user or host """

    pubkey_path = f"{base_dir}/certs/{args.type}/{args.name}.pub"

    if args.type == "user":
        cmd = f"ssh-keygen -s {base_dir}/user_CA -I {args.name} -n {args.name} -V +{args.span} {pubkey_path}"

    if args.type == "account":
        cmd = f"ssh-keygen -s {base_dir}/user_CA -I {args.name} -n {args.name} {pubkey_path}"

    if args.type == "host":
        cmd = f"ssh-keygen -s {base_dir}/host_CA -I {args.name} -h -n {args.name} {pubkey_path}"

    # generate cert
    if os.path.exists(pubkey_path):
        subprocess.run(cmd, shell=True, text=False, check=True, capture_output=True)
        print(f"certificate generated for: {args.name}")


@errorcheck
def revoke_cert(args):
    """ adds users pub key to revoked_certs """
    if not os.path.exists(f"{base_dir}/revoked_keys"):
        os.mknod(f"{base_dir}/revoked_keys")

    if os.path.exists(f"{base_dir}/certs/{args.type}/{args.name}.pub"):
        try:
            print(f"adding {args.name} to revoked_keys file")
            with open(f"{base_dir}/certs/{args.type}/{args.name}.pub", "r") as f:
                line = f.read()
                with open(f"{base_dir}/revoked_keys", "a") as rk:
                    rk.write(f"\n{line}\n")
        except OSError as err:
            raise Exception(str(err)) from err
    remove_duplicates(f"{base_dir}/revoked_keys")


@errorcheck
def remove_keys(args):
    """ remove/delete all of user's or host's keys and certs"""

    # remove pub key
    if os.path.exists(f"{base_dir}/certs/{args.type}/{args.name}.pub"):
        try:
            print(f"removing pub key for {args.name}")
            os.remove(f"{base_dir}/certs/{args.type}/{args.name}.pub")
        except OSError:
            pass
    else:
        print(f"no pub key present for {args.name}")

    # remove priv key
    if os.path.exists(f"{base_dir}/certs/{args.type}/{args.name}"):
        try:
            print(f"removing priv key for {args.name}")
            os.remove(f"{base_dir}/certs/{args.type}/{args.name}")
        except OSError:
            pass
    else:
        print(f"no priv key present for {args.name}")

    # remove
    if os.path.exists(f"{base_dir}/certs/{args.type}/{args.name}-cert.pub"):
        try:
            print(f"removing cert for {args.name}")
            os.remove(f"{base_dir}/certs/{args.type}/{args.name}-cert.pub")
        except OSError:
            pass
    else:
        print(f"no cert present for {args.name}")


@errorcheck
def new_keys(args):
    """ generate new priv/pub keypair """

    print(f"generating keypair for: {args.name}")

    # remove previous keys
    remove_keys(args)

    # generate keypair
    cmd = f"ssh-keygen -t ed25519 -N '' -C '{args.name}@ssh_CA' -f {base_dir}/certs/{args.type}/{args.name}"
    subprocess.run(cmd, shell=True, text=False, check=True, capture_output=True)
    return f"key pair generated: {args.name}"


@errorcheck
def send_user(args):
    """ send email containing keys + cert to user """
    if args.type == "user":
        if args.action == "create":
            print("emailing Cert, SSH keys to user")
            body = f"""
<div style='font-family:Arial;font-size:10pt'>
Here are your SSH key pairs and a certificate.<br><br>

attached are
<ul>
<li>private key ({args.name})</li>
<li>public key ({args.name}.pub)</li>
<li>certificate ({args.name}-cert.pub)</li>
<li>known_hosts file</li>
</ul>
<br>

To login to QB hosts you must copy these files to your Home .ssh directory
<br><br>
download these files and move them to <b>~/.ssh/</b> folder (/Users/{args.name}/.ssh)
<br><br>
open up terminal, then copy and paste this command:

<pre style="padding:10px;background: #e0e0e0;width:400px;">
<code>
chmod 700 ~/.ssh;
chmod 400 ~/.ssh/{args.name};
chmod 640 ~/.ssh/{args.name}.pub;
chmod 600 ~/.ssh/{args.name}-cert.pub;
</code>
</pre>

create a SSH config file
<blockquote>
<code>
vi ~/.ssh/config
</code>
</blockquote>

add this line to the config file to allow you to SSH with a certificate.

<pre style="padding:10px;background: #e0e0e0;width:400px;">
<code>
Host *
    CertificateFile ~/.ssh/{args.name}-cert.pub
    IdentityFile ~/.ssh/{args.name}
    UserKnownHostsFile ~/.ssh/known_hosts
    TCPKeepAlive yes
    ServerAliveInterval 120
    Compression yes
</code>
</pre>

certificate will expire in {args.span} and will automatically regenerate.
<br><br>
Once it expires, you will recieve a new email with new certificate.
</div>
"""
            path = f"{base_dir}/certs/{args.type}"
            files = [f"{path}/{args.name}", f"{path}/{args.name}.pub", f"{path}/{args.name}-cert.pub", f"{base_dir}/known_hosts"]

        if args.action == "regen":
            print("emailing Cert to user")
            body = f"""
This is your regenerated SSH certificate (will expire in {args.span})<br><br>

place this certificate into your <b>~/.ssh</b> directory
            """
            files = [f"{base_dir}/certs/{args.type}/{args.name}-cert.pub"]

        send_email(f"{args.name}@company.com", from_email,
                   None, None, "Your SSH certificate", body, files)


@errorcheck
def check_expiration():
    """ check when cert is expiring, regen and email new cert to user """

    print("checking user cert expiration")

    today = datetime.now()

    for path in pathlib.Path(f"{base_dir}/certs/user").iterdir():
        if path.is_file():
            name = path.stem
            # args = argparse.Namespace(name=name.split("-")[0], path="users", type="human", span=default_span)
            if name.endswith("-cert"):
                cmd = f"ssh-keygen -L -f {path} | grep 'Valid: from'"

                result = subprocess.run(cmd, shell=True, text=True, check=False, capture_output=True).stdout

                if result:
                    result = result.split("to")[1].strip()
                    exp = datetime.strptime(result, "%Y-%m-%dT%H:%M:%S")
                    diff = (today - exp).days
                    if diff > -5:
                        args = argparse.Namespace(name=name.split("-")[0], path="users", type="user", action="regen", span=default_span)
                        gen_cert(args)
                        send_user(args)


if __name__ == "__main__":

    args = parser.parse_args()

    if args.action == "expiration":
        check_expiration()
        sys.exit()

    if args.name is None or args.type is None:
        parser.error("--name requires user or host name, --type required ['user', 'account', 'host']")

    if args.action == "regen":
        gen_cert(args)
        send_user(args)
        sys.exit()

    if args.action == "create":
        revoke_cert(args)
        remove_keys(args)
        new_keys(args)
        gen_cert(args)
        send_user(args)
        # remove user's priv key
        if args.type == "user":
            os.remove(f"{base_dir}/certs/{args.type}/{args.name}")
        sys.exit()

    if args.action == "remove":
        revoke_cert(args)
        remove_keys(args)
        sys.exit()

    if args.action == "revoke":
        revoke_cert(args)
        sys.exit()
