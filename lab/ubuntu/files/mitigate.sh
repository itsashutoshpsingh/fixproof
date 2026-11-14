#!/bin/bash
# State S5: the vendor-documented mitigations, applied to the vulnerable packages.
set -eux
# CVE-2024-6387 (regreSSHion): LoginGraceTime 0 (Qualys advisory, Ubuntu security notes)
# CVE-2023-48795 (Terrapin): disable chacha20-poly1305 and the EtM MACs (terrapin-attack.com)
# sshd uses the first value it reads, so the lines go at the top of the main config
sed -i '1i LoginGraceTime 0\nCiphers -chacha20-poly1305@openssh.com\nMACs -*-etm@openssh.com' /etc/ssh/sshd_config
# CVE-2021-4034 (PwnKit): remove the setuid bit from pkexec (Qualys, Red Hat)
[ -e /usr/bin/pkexec ] && chmod 0755 /usr/bin/pkexec
# CVE-2023-22809 (sudoedit): strip editor variables for sudoedit (sudo.ws advisory)
[ -e /etc/sudoers ] && echo 'Defaults!sudoedit env_delete+="SUDO_EDITOR VISUAL EDITOR"' > /etc/sudoers.d/90-mitigation && chmod 0440 /etc/sudoers.d/90-mitigation
# CVE-2024-2961 (glibc iconv): disable the ISO-2022-CN-EXT converter (Red Hat RHSB-2024-002 style)
for f in /usr/lib/x86_64-linux-gnu/gconv/gconv-modules /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.d/gconv-modules-extra.conf; do
  [ -e "$f" ] && sed -i -E 's/^(alias\s+ISO-IR-165\/\/|alias\s+ISO2022CNEXT\/\/|module\s+.*ISO-2022-CN-EXT.*)/#&/' "$f"
done
iconvconfig || true
