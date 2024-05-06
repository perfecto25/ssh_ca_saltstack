## SSH CA for each server

user_CA_pubkey:
  file.managed:
    - name: /etc/ssh/user_CA.pub
    - source: salt://ssh_ca/user_CA.pub
    - user: root
    - group: root
    - mode: "0600"

host_priv_key:
  file.managed:
    - name: /etc/ssh/{{grains.id}}
    - source: salt://ssh_ca/certs/host/{{grains.id}}
    - user: root
    - group: root
    - mode: "0600"

host_pub_key:
  file.managed:
    - name: /etc/ssh/{{grains.id}}.pub
    - source: salt://ssh_ca/certs/host/{{grains.id}}.pub
    - user: root
    - group: root
    - mode: "0640"

host_cert:
  file.managed:
    - name: /etc/ssh/{{grains.id}}-cert.pub
    - source: salt://ssh_ca/certs/host/{{grains.id}}-cert.pub
    - user: root
    - group: root
    - mode: "0640"

host_known_hosts:
  file.managed:
    - name: /etc/ssh/ssh_known_hosts
    - source: salt://ssh_ca/known_hosts
    - user: root
    - group: root
    - mode: "0640"

host_revoked_keys:
  file.managed:
    - name: /etc/ssh/revoked_keys
    - source: salt://ssh_ca/revoked_keys
    - user: root
    - group: root
    - mode: "0640"

## General SSHD config
{% set pkgs = ['openssh', 'openssh-clients', 'openssh-server'] %}
{% for pkg in pkgs %}
  {{ pkg }}:
    pkg.installed:
      - name: openssh-server
{% endfor %}
    
sshd_config:
  file.managed:
    - name: /etc/ssh/sshd_config
      - source: 
        - salt://{{ slspath }}/sshd_config.j2
    - template: jinja
    - user: root
    - group: root
    - mode: "0600"

host_ecdsa_priv_remove:
  file.absent:
    - name: /etc/ssh/ssh_host_ecdsa_key
    
host_ecdsa_pub_remove:
  file.absent:
    - name: /etc/ssh/ssh_host_ecdsa_key.pub
    
host_rsa_priv_remove:
  file.absent:
    - name: /etc/ssh/ssh_host_rsa_key
    
host_rsa_pub_remove:
  file.absent:
    - name: /etc/ssh/ssh_host_rsa_key.pub

sshd_service:
  service.running:
    - name: sshd
    - enable: True
    - reload: True
    - watch:
      - file: sshd_config
