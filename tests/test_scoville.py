import json

import pytest

from scoville import (
    INCIDENTS,
    RULES,
    ConfigError,
    analyze,
    apply_overrides,
    band,
    entry_by_id,
    find_config,
    generic_clis,
    load_config,
    main,
    overall,
    rule_ids,
    specific_clis,
    split_commands,
    why_text,
)


def one(cmd, **kw):
    results = analyze(cmd, **kw)
    assert results, f"no result for {cmd!r}"
    return max(results, key=lambda r: r["score"])


def level(cmd, **kw):
    return one(cmd, **kw)["level"]


def score(cmd, **kw):
    return one(cmd, **kw)["score"]


# --- the escalation the tool exists for ------------------------------------

def test_rm_escalates_with_flags_then_target():
    plain = score("rm notes.txt")
    recursive = score("rm -rf ./build-output")
    root = score("rm -rf /")
    assert plain < recursive < root
    assert level("rm notes.txt") == "medium"
    assert level("rm -rf /") == "critical"
    assert one("rm -rf /")["reversibility"] == "irreversible"


def test_no_preserve_root_is_worse_than_root_alone():
    assert score("rm -rf --no-preserve-root /") >= score("rm -rf /")


def test_system_dirs_escalate_but_build_dirs_dampen():
    assert level("rm -rf /etc") == "critical"
    assert score("rm -rf node_modules") < score("rm -rf /srv/data")


def test_unset_variable_expanding_to_root():
    r = one("rm -rf $DIR/")
    assert r["level"] == "critical"
    assert any("unset" in f["why"] for f in r["factors"])


def test_aws_read_is_free_write_is_not():
    assert level("aws s3 ls") == "safe"
    assert level("aws s3api list-buckets") == "safe"
    assert level("aws s3api delete-bucket --bucket assets") == "high"
    assert level("aws s3 rm s3://assets --recursive") == "critical"
    assert score("aws rds delete-db-instance --db-instance-identifier db "
                 "--skip-final-snapshot") == 100


def test_ifup_is_fine_ifdown_is_not():
    assert level("ifup eth0") == "safe"
    assert level("ifdown eth0") == "medium"
    assert one("ifdown eth0")["scope"] == "network"


# --- carriers: the payload is the risk, not the wrapper --------------------

def test_docker_exec_scored_on_its_payload():
    assert level("docker exec web ls /app") == "low"
    assert level("docker exec web rm -rf /") == "critical"
    assert score("docker exec web rm -rf /") > score("docker exec web rm -rf /tmp/cache")


def test_docker_exec_payload_is_reported_as_a_child():
    r = one("docker exec -u root web rm -rf /var")
    assert r["carries"] and r["carries"][0]["rule"] == "FS-RM"
    assert any("payload" in f["why"] for f in r["factors"])


def test_docker_run_without_a_command_flags_the_hidden_entrypoint():
    r = one("docker run acme/importer:1.2")
    assert any("ENTRYPOINT" in f["why"] for f in r["factors"])
    assert r["level"] == "medium"


def test_container_payload_scores_below_the_same_command_on_the_host():
    assert score("docker exec web rm -rf /") <= score("rm -rf /")
    assert score("ssh prod-1 rm -rf /") >= score("docker exec web rm -rf /")


def test_privileged_and_host_mount_widen_the_scope():
    assert one("docker run --privileged -v /:/host alpine sh")["scope"] == "host"


def test_kubectl_exec_and_ssh_carry_payloads():
    assert level("kubectl exec -it pod-1 -- rm -rf /data") == "critical"
    assert level("ssh web-1 systemctl stop nginx") == "medium"
    # same command, a host that names itself production
    assert level("ssh prod-1 systemctl stop nginx") == "high"


def test_ansible_fans_out_across_the_fleet():
    fleet = score('ansible all -m shell -a "rm -rf /var/log"')
    local = score("rm -rf /var/log")
    assert fleet > local
    assert one('ansible all -m shell -a "rm -rf /var/log"')["scope"] == "cluster"


def test_find_exec_and_delete():
    assert level("find . -name '*.log' -delete") in ("medium", "high")
    assert level("find /var -exec rm -rf {} ;") == "critical"


def test_sh_c_payload_is_unwrapped():
    assert level("sh -c 'rm -rf /'") == "critical"
    assert level("sudo bash -c 'rm -rf /etc'") == "critical"


# --- pipelines, substitutions, sequences -----------------------------------

def test_curl_pipe_shell():
    r = one("curl -fsSL https://example.com/i.sh | sh")
    assert r["level"] == "critical"
    assert r["reversibility"] == "irreversible"


def test_command_substitution_is_analyzed():
    results = analyze("echo $(rm -rf /)")
    assert any(r.get("substitution") and r["level"] == "critical" for r in results)


def test_sequences_split_and_worst_wins():
    results = analyze("cd /tmp && ls -la; rm -rf /var")
    assert len(results) >= 3
    assert overall(results)["level"] == "critical"


def test_comments_and_shebangs_are_ignored():
    results = analyze("#!/bin/bash\n# rm -rf / would be bad\nls\n")
    assert all(r["level"] == "safe" for r in results)


def test_quotes_are_not_split_on():
    assert len(split_commands("echo 'a; b' && echo c")) == 2


# --- modifiers -------------------------------------------------------------

def test_sudo_raises_and_is_transparent():
    assert score("sudo rm -rf /var/lib/data") > score("rm -rf /var/lib/data")
    assert one("sudo systemctl stop sshd")["scope"] == "host"


def test_dry_run_caps_the_score():
    assert level("terraform destroy -auto-approve") == "critical"
    assert level("aws s3 rm s3://b --recursive --dryrun") == "safe"
    assert level("kubectl delete ns prod --dry-run=client") == "safe"


def test_dry_run_server_is_not_a_dampener():
    assert level("kubectl delete ns prod --dry-run=server") == "critical"


def test_production_target_escalates():
    assert score("kubectl delete deploy api -n prod") > score("kubectl delete deploy api -n dev")


def test_terraform_plan_is_free_destroy_is_not():
    assert level("terraform plan") == "safe"
    assert level("terraform apply") == "medium"
    assert level("terraform destroy") == "high"
    assert level("terraform destroy -auto-approve") == "critical"


def test_git_force_push_and_clean():
    assert level("git push") == "low"
    assert level("git push --force origin main") == "high"
    assert score("git push --force origin main") > score("git push --force origin feat-x")
    assert level("git push --force-with-lease origin main") != "critical"
    assert level("git clean -fdx") == "medium"


def test_sql_without_where_clause():
    assert level('psql -c "DROP TABLE users"') == "high"
    assert level('psql -c "DROP DATABASE app"') == "critical"
    assert level('mysql -e "DELETE FROM orders"') == "high"
    assert score('mysql -e "DELETE FROM orders"') > score('mysql -e "DELETE FROM orders WHERE id=1"')
    assert level('psql -c "SELECT count(*) FROM orders"') == "low"
    assert level("redis-cli FLUSHALL") == "critical"


def test_fork_bomb():
    assert level(":(){ :|:& };:") == "critical"


def test_crontab_r():
    assert level("crontab -r") == "high"
    assert level("crontab -l") == "safe"


def test_unknown_command_is_low_unless_strict():
    assert level("frobnicate --all") == "safe"
    assert one("frobnicate --all")["known"] is False
    assert level("frobnicate --all", strict=True) == "medium"


# --- scales and CLI --------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (0, "safe"), (14, "safe"), (15, "low"), (35, "medium"), (60, "high"), (100, "critical"),
])
def test_bands(value, expected):
    assert band(value) == expected


def test_scores_are_clamped():
    assert score("sudo rm -rf --no-preserve-root / /etc /home") == 100


def test_json_output_and_exit_codes(capsys):
    assert main(["ls", "--format", "json"]) == 0
    assert "overall" in capsys.readouterr().out
    assert main(["rm -rf /", "--fail-on", "high"]) == 1
    capsys.readouterr()
    assert main(["ls -la", "--fail-on", "high"]) == 0
    capsys.readouterr()


def test_file_input_reports_line_numbers(tmp_path, capsys):
    script = tmp_path / "deploy.sh"
    script.write_text("#!/bin/sh\nset -e\nls\nrm -rf /opt/app\n")
    assert main(["-f", str(script), "--fail-on", "medium"]) == 1
    out = capsys.readouterr().out
    assert "deploy.sh:4:" in out


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    assert "FS-RM" in capsys.readouterr().out


# --- introspection (faked docker: no daemon required) ----------------------

def test_introspect_resolves_a_dangerous_entrypoint(monkeypatch):
    import scoville
    monkeypatch.setattr(scoville, "shutil", scoville.shutil)
    monkeypatch.setattr(scoville.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(scoville, "_docker",
                        lambda args, timeout=5: '["/bin/sh","-c","rm -rf /data"]|null|root|sha256:x')
    r = one("docker run acme/cleaner:1.0", introspect=True)
    assert r["level"] == "critical"
    assert any("resolved entrypoint" in f["why"] for f in r["factors"])
    assert any("runs as root" in f["why"] for f in r["factors"])


def test_introspect_reports_when_it_cannot_resolve(monkeypatch):
    import scoville
    monkeypatch.setattr(scoville.shutil, "which", lambda _: "/usr/bin/docker")
    monkeypatch.setattr(scoville, "_docker", lambda args, timeout=5: None)
    r = one("docker run acme/cleaner:1.0", introspect=True)
    assert any("cannot inspect" in f["why"] for f in r["factors"])
    assert r["level"] == "medium"


def test_introspect_without_docker_says_so(monkeypatch):
    import scoville
    monkeypatch.setattr(scoville.shutil, "which", lambda _: None)
    r = one("docker run acme/cleaner:1.0", introspect=True)
    assert any("no docker CLI" in f["why"] for f in r["factors"])


def test_introspection_is_opt_in(monkeypatch):
    import scoville

    def boom(*a, **k):
        raise AssertionError("scoville shelled out without --introspect")

    monkeypatch.setattr(scoville, "_docker", boom)
    assert level("docker run acme/cleaner:1.0") == "medium"


def test_a_file_inside_home_is_not_the_home_directory():
    assert level("chmod 600 ~/.ssh/id_rsa") == "low"
    assert level("rm -rf ~") == "critical"


def test_paths_under_a_system_dir_score_below_the_dir_itself():
    under = score("rm -rf /var/lib/mysql")
    exact = score("rm -rf /var")
    assert score("rm -rf ./build") < under < exact


def test_quoted_command_text_is_not_treated_as_a_command():
    assert level('echo "rm -rf /"') == "safe"


# --- the long tail of resource CLIs ----------------------------------------

@pytest.mark.parametrize("cmd", [
    "hcloud server delete my-db",
    "scw instance server terminate 11111111",
    "doctl compute droplet delete web-1",
    "linode-cli linodes delete 123",
    "flyctl apps destroy api",
    "wrangler r2 bucket delete assets",
    "pscale database delete app main",
    "incus delete web-1",
    "openstack server delete web-1",
])
def test_destructive_verbs_across_cloud_clis(cmd):
    assert level(cmd) in ("high", "critical")


@pytest.mark.parametrize("cmd", [
    "hcloud server list",
    "scw instance server list",
    "doctl compute droplet list",
    "gh pr list",
    "zfs list",
    "velero backup describe daily-1",
])
def test_read_verbs_stay_free(cmd):
    assert level(cmd) == "safe"


def test_a_resource_named_delete_does_not_make_a_read_destructive():
    assert level("hcloud server describe delete-me") == "safe"


def test_write_verbs_sit_between():
    assert level("gh pr create --title x") == "low"
    assert level("doctl compute droplet create web-1 --size s-1vcpu-1gb") == "low"


def test_promoting_a_cli_can_move_a_verb_off_the_generic_score():
    # `flyctl deploy` was `low` under verb classification, which scores every
    # write the same. A Fly deploy is a release to production, so promoting the
    # CLI moves it deliberately — this is the recalibration the promotion buys,
    # not a drift.
    assert level("flyctl deploy") == "medium"


def test_specific_rules_beat_generic_verbs_even_when_lower():
    # `virsh destroy` powers a domain off, it does not delete it
    assert score("virsh destroy vm1") < score("virsh undefine vm1")
    assert level("virsh destroy vm1") == "medium"


def test_rclone_sync_deletes_at_the_destination():
    assert level("rclone sync /src remote:bucket") == "medium"
    assert score("rclone purge remote:bucket") > score("rclone sync /src remote:bucket")


def test_backup_tools_are_scored_on_the_copy_of_last_resort():
    assert level("restic forget --prune --keep-last 1") == "high"
    assert level("velero backup delete daily-1") == "high"


def test_etcd_prefix_delete_is_cluster_state():
    assert level("etcdctl del --prefix ''") == "critical"


def test_an_unknown_cli_with_a_destructive_verb_is_never_safe():
    assert level("frobctl delete cluster prod") == "high"
    assert one("frobctl delete cluster prod")["known"] is False
    assert level("frobctl list") == "safe"


def test_find_fans_out_over_the_match_set():
    assert score(r"find . -exec rm {} \;") > score("rm notes.txt")
    assert score("find / -type f -exec shred {} +") == 100


# --- generic arguments: the same signal on any binary ----------------------

def test_secret_on_the_command_line():
    r = one("mysql -h db --password=hunter2 -e 'SELECT 1'")
    assert any("visible to every user" in f["why"] for f in r["factors"])
    assert score("curl --token=abc123 https://api.example.com") > score("curl https://api.example.com")


def test_verification_disabled_is_generic():
    assert score("helm upgrade api ./c --skip-tls-verify") > score("helm upgrade api ./c")
    assert score("apt-get install -y --allow-unauthenticated foo") > score("apt-get install -y foo")
    # the same flag must not be counted by both a specific and the generic amp
    assert score("curl -k https://x") == score("curl --insecure https://x")


def test_open_to_the_world_is_generic():
    assert level("gcloud compute firewall-rules create open --source-ranges=0.0.0.0/0") == "high"
    assert one("frobctl allow --cidr ::/0")["scope"] == "network"


def test_softeners_lower_the_careful_form():
    assert score("rm -ri /tmp/cache") < score("rm -rf /tmp/cache")
    assert score("sed -i.bak 's/a/b/' app.conf") < score("sed -i 's/a/b/' app.conf")
    assert score("git push --force-with-lease origin main") < score("git push --force origin main")
    assert score("ansible all -m shell -a 'rm -rf /tmp/x' --limit web-1") < \
        score("ansible all -m shell -a 'rm -rf /tmp/x'")


def test_a_rule_does_not_also_collect_the_amp_it_exists_for():
    generic = "get past the check"
    # GIT-PUSH-F already scores --force, so the generic FORCE amp must not stack
    assert not [f for f in one("git push --force origin main")["factors"] if generic in f["why"]]
    # …but a binary with no force rule of its own still gets it
    assert [f for f in one("frobctl delete cluster --force")["factors"] if generic in f["why"]]


def test_decoding_into_a_shell_is_the_same_as_downloading_into_one():
    assert level("echo cm0K | base64 -d | sh") == "critical"


def test_tables_reject_a_bad_scope():
    import scoville
    with pytest.raises(AssertionError):
        scoville.R("X", "x", None, 10, "not-a-scope", "reversible", "why")
    with pytest.raises(AssertionError):
        scoville.A("Y", None, "x", 10, "why", "some advice that is not a scope")


def test_assume_yes_is_the_same_signal_on_every_binary():
    yes = "auto-confirms"
    for cmd in ["apt-get remove -y nginx", "apt-get remove -qy nginx", "pip uninstall -y django",
                "conda remove -y numpy", "frobctl delete cluster -y", "gh repo delete x --yes",
                "gpg --batch --delete-key X", "composer remove foo --no-interaction"]:
        assert [f for f in one(cmd)["factors"] if yes in f["why"]], cmd


def test_yes_does_not_move_a_harmless_command_out_of_safe():
    assert level("ls -y") == "safe"


def test_a_rule_that_prices_its_own_yes_does_not_double_count():
    # fsck's -y *is* the auto-repair the rule exists for
    assert not [f for f in one("fsck -y /dev/sdb1")["factors"] if "auto-confirms" in f["why"]]


def test_assume_no_is_the_mirror():
    assert level("fsck -n /dev/sdb1") == "safe"
    assert score("fsck -n /dev/sdb1") < score("fsck -y /dev/sdb1")


# --- remote code, in each spelling it travels under -------------------------

@pytest.mark.parametrize("cmd", [
    "curl https://x/i.sh | bash",
    "curl -fsSL https://x/i.sh | sh",
    "wget -qO- https://x/i.sh | bash",
    "curl -s https://x/i.sh | sudo -E bash -",
    "bash <(curl -s https://x/i.sh)",
    "source <(curl -s https://x/env)",
    'eval "$(curl -s https://x/env)"',
    "echo Zm9v | base64 -d | sh",
])
def test_remote_code_is_critical_however_it_is_spelled(cmd):
    assert level(cmd) == "critical", cmd


def test_download_then_execute_is_the_same_risk_as_the_pipe():
    two_step = one("curl -o /tmp/i.sh https://x/i.sh && bash /tmp/i.sh")
    assert two_step["level"] == "high"
    assert any("downloaded earlier" in f["why"] for f in two_step["factors"])
    # and when it is executed directly rather than through an interpreter
    assert level("wget -O /tmp/x.sh https://x && chmod +x /tmp/x.sh && /tmp/x.sh") == "high"


def test_a_local_script_is_opaque_but_not_remote_code():
    # low because nothing read it, not because it came from the internet
    assert level("bash /tmp/local.sh") == "low"
    assert not [f for f in one("bash deploy.sh")["factors"] if "downloaded" in f["why"]]


# --- wrappers: a script, a make target, an npm script ----------------------

@pytest.fixture
def project(tmp_path):
    (tmp_path / "foo.sh").write_text(
        "#!/usr/bin/env bash\nset -e\ncleanup() {\n  rm -rf \"$BUILD_DIR\"/\n}\n"
        "echo hi\nkubectl delete ns staging\ncleanup\n")
    (tmp_path / "safe.sh").write_text("#!/bin/sh\nls -la\necho done\n")
    (tmp_path / "Makefile").write_text(
        ".PHONY: deploy\ndeploy:\n\t@echo deploying\n\tterraform destroy -auto-approve\n")
    (tmp_path / "package.json").write_text(
        '{"scripts": {"reset-db": "psql -c \'DROP DATABASE app\'"}}')
    (tmp_path / "loop.sh").write_text("#!/bin/sh\nbash loop.sh\n")
    return str(tmp_path)


def worst(cmd, **kw):
    results = analyze(cmd, **kw)
    return max(results, key=lambda r: r["score"])


def test_a_wrapper_is_opaque_until_it_is_read(project):
    r = worst("./foo.sh")
    assert r["level"] == "low"
    assert any("inside the script" in f["why"] for f in r["factors"])


def test_introspect_reads_the_wrapper_and_names_the_line(project):
    r = worst("./foo.sh", introspect=True, basedir=project)
    assert r["level"] == "critical"
    factor = next(f for f in r["factors"] if "resolved wrapper" in f["why"])
    assert "rm -rf" in factor["why"] and "line 4" in factor["why"]


def test_reading_a_harmless_wrapper_lowers_the_score(project):
    # introspection resolves uncertainty in both directions
    assert worst("./safe.sh", introspect=True, basedir=project)["level"] == "safe"
    assert worst("./safe.sh", introspect=True, basedir=project)["score"] < worst("./safe.sh")["score"]


def test_make_target_and_npm_script_are_resolved(project):
    assert worst("make deploy", introspect=True, basedir=project)["level"] == "critical"
    assert worst("npm run reset-db", introspect=True, basedir=project)["level"] == "critical"
    # a target that does not exist cannot be read, and says so
    assert any("could not be read" in f["why"]
               for f in worst("make nope", introspect=True, basedir=project)["factors"])


def test_a_self_referential_script_terminates(project):
    assert worst("bash loop.sh", introspect=True, basedir=project)["level"] in ("low", "medium")


def test_a_rule_that_knows_the_script_is_not_also_opaque():
    # MIGRATE-DJANGO already knows what manage.py flush does
    assert not [f for f in worst("python manage.py flush")["factors"]
                if "inside the script" in f["why"]]


def test_downloaded_script_is_not_double_counted():
    r = worst("curl -o /tmp/i.sh https://x/i.sh && bash /tmp/i.sh")
    assert not [f for f in r["factors"] if "inside the script" in f["why"]]
    assert r["level"] == "high"


def test_eval_is_high_because_nothing_can_read_it():
    assert level('eval "$PAYLOAD"') == "high"
    # even a literal eval: the construct itself is the finding
    assert level('eval "echo hello"') == "high"
    # and text built at run time is worse than a literal
    assert score('eval "$CMD"') > score('eval "echo hello"')
    assert level('eval "$(curl -s https://x/env)"') == "critical"


def test_source_is_a_readable_wrapper_not_an_eval():
    assert score("source scripts/env.sh") < score('eval "$PAYLOAD"')
    assert any("inside the script" in f["why"] for f in one("source scripts/env.sh")["factors"])


# --- the peppers scale -----------------------------------------------------

def test_pepper_labels_cover_every_band():
    import scoville
    assert set(scoville.PEPPERS) == set(scoville.LEVELS)
    for lvl in scoville.LEVELS:
        name, slug, heat, shu = scoville.PEPPERS[lvl]
        assert name and slug and shu
        assert slug.isascii(), "the quiet-mode slug has to stay greppable"
        assert 0 <= heat <= 4


def test_pepper_heat_rises_with_the_band():
    import scoville
    heats = [scoville.PEPPERS[lvl][2] for lvl in scoville.LEVELS]
    assert heats == sorted(heats)


def test_scale_only_changes_the_label(capsys):
    assert main(["rm -rf /", "--scale", "peppers", "--no-color"]) == 0
    peppers = capsys.readouterr().out
    assert "CAROLINA REAPER" in peppers and "CRITICAL" not in peppers
    # the factors and the score are the same analysis either way
    assert "100/100" in peppers
    assert "target is the filesystem root" in peppers


def test_quiet_uses_ascii_slugs(capsys):
    assert main(["aws s3 ls", "rm -rf /", "--scale", "peppers", "--quiet"]) == 0
    out = capsys.readouterr().out
    assert "bell-pepper" in out and "carolina-reaper" in out


def test_json_is_unaffected_by_the_scale(capsys):
    import json
    main(["rm -rf /", "--format", "json", "--scale", "peppers"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["overall"]["level"] == "critical", "machine output stays on the bands"


def test_fail_on_still_works_with_peppers(capsys):
    assert main(["rm -rf /", "--scale", "peppers", "--fail-on", "high", "--quiet"]) == 1
    capsys.readouterr()


# --- shell functions and aliases defined in the analysed text ---------------
#
# A helper defined in the script is a carrier like any other wrapper: the call
# site shows nothing, and in a deploy script that defines its own functions
# that is most of the interesting lines.

FUNC_SCRIPT = """\
alias k=kubectl
deploy() { kubectl delete ns "$1"; kubectl apply -f manifests/; }
deploy prod
k delete ns prod
"""


def line(text, needle, **kw):
    """The result for the command containing `needle`."""
    for r in analyze(text, **kw):
        if needle in r["command"]:
            return r
    raise AssertionError(f"no command matching {needle!r}")


def test_a_function_call_is_scored_as_its_body():
    call = line(FUNC_SCRIPT, "deploy prod", introspect=True)
    assert call["level"] == "high"
    assert call["scope"] == "cluster" and call["reversibility"] == "irreversible"
    # The definition site is in the trace, so the reader can find the body.
    assert "defined on line 2" in call["factors"][0]["why"]
    assert "kubectl delete ns" in call["factors"][1]["why"]


def test_an_alias_shadowing_a_binary_is_expanded():
    call = line(FUNC_SCRIPT, "k delete ns prod", introspect=True)
    # Scored as the kubectl command it really is, not as an unknown CLI.
    assert call["level"] == "critical"
    assert "resolved alias `k` is `kubectl`" in call["factors"][0]["why"]
    assert "kubectl delete ns prod" in call["factors"][0]["why"]


def test_resolution_is_opt_in():
    # Without --introspect the tool scores exactly what it is shown. `deploy`
    # is an unknown command and `k` an unknown CLI hitting the verb floor.
    assert line(FUNC_SCRIPT, "deploy prod")["level"] == "low"
    assert line(FUNC_SCRIPT, "k delete ns prod")["level"] == "high"
    assert line(FUNC_SCRIPT, "deploy prod", introspect=True)["level"] == "high"


def test_a_function_defined_after_the_call_is_not_applied():
    # bash reads top to bottom: at line 1 `cleanup` is not a function yet, and
    # scoring it as one would be a false positive on a very common layout.
    text = 'cleanup prod\ncleanup() { rm -rf /var/lib/data; }\n'
    call = line(text, "cleanup prod", introspect=True)
    assert call["rule"] == "UNKNOWN"
    assert call["level"] == "low"


def test_the_last_definition_before_the_call_wins():
    text = 'sync() { echo safe; }\nsync() { rm -rf /; }\nsync now\n'
    call = line(text, "sync now", introspect=True)
    assert "defined on line 2" in call["factors"][0]["why"]
    assert call["level"] == "critical"


def test_a_name_is_resolved_at_the_call_site_not_the_definition():
    # `a` is defined above `b` but called below both, so `b` is in scope by the
    # time `a` runs — resolving at definition time would miss the rm entirely.
    text = 'a() { b; }\nb() { rm -rf /etc; }\na\n'
    call = analyze(text, introspect=True)[-1]
    assert call["command"] == "a"
    assert call["level"] == "critical"


def test_direct_recursion_terminates_and_still_scores_the_body():
    text = 'loop() { loop; rm -rf /tmp/x; }\nloop\n'
    results = analyze(text, introspect=True)
    call = results[-1]
    assert call["command"] == "loop"
    # The recursive arm stops; the arm that does real work is still counted.
    assert "rm -rf /tmp/x" in call["factors"][1]["why"]


def test_mutual_recursion_terminates():
    text = 'a() { b; }\nb() { a; rm -rf /etc; }\na\n'
    results = analyze(text, introspect=True)  # must not hang or recurse away
    assert results[-1]["level"] == "critical"


def test_calling_the_same_helper_twice_scores_both_calls():
    # The cycle guard is a call *stack*, not a visited set: a second, separate
    # call is ordinary and must not be reported as recursion.
    text = 'wipe() { rm -rf /var/lib/data; }\nwipe\nwipe\n'
    results = [r for r in analyze(text, introspect=True) if r["command"] == "wipe"]
    assert len(results) == 2
    assert results[0]["score"] == results[1]["score"] > 0
    assert all(r["rule"] == "CARRIER-FUNCTION" for r in results)


def test_nothing_outside_the_analysed_text_is_read(tmp_path, monkeypatch):
    # Reading ~/.bashrc would make the same script score differently on two
    # machines, which is a worse answer than an unknown command.
    bashrc = tmp_path / ".bashrc"
    bashrc.write_text("alias deploy='rm -rf /'\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    call = line("deploy prod", "deploy prod", introspect=True)
    assert call["rule"] == "UNKNOWN"
    assert call["level"] == "low"


def test_an_unterminated_function_body_is_skipped_not_half_scored():
    text = 'broken() { rm -rf /\ndeploy prod\n'
    # No closing brace: scoring half a body is worse than not resolving it.
    assert line(text, "deploy prod", introspect=True)["rule"] == "UNKNOWN"


def test_a_function_body_containing_braces_is_read_whole():
    # `${VAR}` puts a brace pair inside the body. A non-greedy match to the
    # first `}` would truncate here and silently under-report what runs.
    text = 'go() { rm -rf "${TARGET}"/data; }\ngo\n'
    call = analyze(text, introspect=True)[-1]
    assert call["command"] == "go"
    assert call["score"] > 0, "brace counting truncated the body"
    assert "rm -rf" in call["factors"][1]["why"]


# --- .scovillerc overrides -------------------------------------------------
#
# Risk is contextual. Before this the only levers were --fail-on and --strict,
# both global, so the first time a legitimate command tripped the gate the
# cheapest fix was to turn the gate off. That is the failure mode being
# designed against, so the tests care as much about what stays visible as about
# what changes.

RC = {
    "allow": [{"match": "kubectl delete ns ci-*", "why": "routine CI teardown"}],
    "deny": [{"match": "*--context prod*", "why": "prod goes through the pipeline"}],
    "rescore": [{"match": "terraform apply*", "level": "critical", "why": "shared state"}],
}


@pytest.fixture
def rc(tmp_path):
    (tmp_path / ".scovillerc").write_text(json.dumps(RC))
    return tmp_path


def scored(command, entries):
    return apply_overrides(analyze(command), entries)[0]


def test_config_is_discovered_from_the_directory_upwards(rc):
    deep = rc / "a" / "b"
    deep.mkdir(parents=True)
    # A repo-root config covers every subdirectory: risk is a property of the
    # repository, not of the directory you happened to run from.
    assert find_config(str(deep)) == str(rc / ".scovillerc")
    assert find_config(str(rc)) == str(rc / ".scovillerc")


def test_allow_keeps_the_real_score_but_does_not_trip_the_gate(rc, capsys):
    entries = load_config(str(rc / ".scovillerc"))
    r = scored("kubectl delete ns ci-1234", entries)
    # Reporting it as safe would be a lie; the finding stays, with its score.
    assert r["level"] == "high" and r["score"] == 80
    assert r["override"]["action"] == "allow"
    assert "routine CI teardown" in r["factors"][-1]["why"]

    code = main(["kubectl delete ns ci-1234", "--fail-on", "high",
                 "--config", str(rc / ".scovillerc")])
    assert code == 0


def test_an_unallowed_command_still_trips_the_gate(rc):
    assert main(["kubectl delete ns prod", "--fail-on", "high",
                 "--config", str(rc / ".scovillerc")]) == 1


def test_deny_forces_critical_whatever_the_command_scores(rc):
    entries = load_config(str(rc / ".scovillerc"))
    # A read-only command, denied: the point is that it is never acceptable
    # here, not that it is dangerous.
    r = scored("kubectl get pods --context prod-eu", entries)
    assert r["level"] == "critical" and r["score"] == 100
    assert "prod goes through the pipeline" in r["factors"][-1]["why"]


def test_deny_beats_allow_when_both_match(tmp_path):
    cfg = tmp_path / ".scovillerc"
    cfg.write_text(json.dumps({
        "allow": [{"match": "rm *", "why": "we delete a lot"}],
        "deny": [{"match": "rm -rf /*", "why": "no"}],
    }))
    entries = load_config(str(cfg))
    # A deny has to survive an allow written by someone who did not know about it.
    assert scored("rm -rf /var", entries)["override"]["action"] == "deny"
    assert scored("rm notes.txt", entries)["override"]["action"] == "allow"


def test_rescore_pins_the_band_and_says_what_moved(rc):
    entries = load_config(str(rc / ".scovillerc"))
    r = scored("terraform apply", entries)
    assert r["level"] == "critical"
    assert "re-scored medium → critical" in r["factors"][-1]["why"]
    assert "shared state" in r["factors"][-1]["why"]


def test_an_override_is_visible_in_json(rc, capsys):
    main(["terraform apply", "--format", "json", "--config", str(rc / ".scovillerc")])
    payload = json.loads(capsys.readouterr().out)
    override = payload["commands"][0]["override"]
    assert override == {"action": "rescore", "match": "terraform apply*",
                        "why": "shared state", "level": "critical"}


def test_strict_does_not_defeat_an_allow(tmp_path):
    cfg = tmp_path / ".scovillerc"
    cfg.write_text(json.dumps({"allow": [{"match": "frobnicate *", "why": "ours"}]}))
    # --strict raises unknown commands; an explicit allow still holds the gate
    # open, because the repo has said it knows what this one is.
    assert main(["frobnicate the-thing", "--strict", "--fail-on", "medium",
                 "--config", str(cfg)]) == 0
    assert main(["frobnicate the-thing", "--strict", "--fail-on", "medium"]) == 1


def test_no_config_ignores_a_discovered_file(rc, monkeypatch):
    monkeypatch.chdir(rc)
    assert main(["kubectl delete ns ci-1", "--fail-on", "high"]) == 0
    assert main(["kubectl delete ns ci-1", "--fail-on", "high", "--no-config"]) == 1


def test_every_override_must_state_a_reason(tmp_path):
    cfg = tmp_path / ".scovillerc"
    cfg.write_text(json.dumps({"allow": [{"match": "rm *"}]}))
    # An override with no stated reason is how a config file becomes a list
    # nobody can safely delete from.
    with pytest.raises(ConfigError, match="needs a `why`"):
        load_config(str(cfg))


def test_a_malformed_config_is_refused_not_guessed_at(tmp_path):
    cfg = tmp_path / ".scovillerc"
    for bad, msg in (
        ({"rescore": [{"match": "x", "why": "y", "level": "nope"}]}, "must be one of"),
        ({"oops": []}, "unknown key"),
        ({"allow": [{"why": "no match"}]}, "needs a `match`"),
        ([], "expected an object"),
    ):
        cfg.write_text(json.dumps(bad))
        with pytest.raises(ConfigError, match=msg):
            load_config(str(cfg))
    cfg.write_text("not json")
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(str(cfg))


def test_a_named_config_that_is_missing_is_an_error(tmp_path):
    # Running without the policy the caller asked for would silently apply a
    # different one than they think is in force.
    assert main(["ls", "--config", str(tmp_path / "nope.json")]) == 64


# --- promoted CLIs, and the floor underneath everything else ----------------

def rule_id(cmd):
    return one(cmd)["rule"]


PROMOTED = ("vault", "velero", "argocd", "openstack", "flyctl", "gh")


def test_the_promoted_clis_have_rules_of_their_own():
    assert set(PROMOTED) <= set(specific_clis())


@pytest.mark.parametrize("cli", ["hcloud", "doctl", "scw", "linode-cli", "wrangler", "pscale"])
def test_verb_classification_still_carries_the_clis_nobody_promoted(cli):
    # The floor is the reason a gate is worth having on day one of a new CLI.
    # Promoting six of them must not quietly remove it from the other forty.
    assert cli in generic_clis()
    assert rule_id(f"{cli} server delete web-1") == "CLI-DESTROY"
    assert level(f"{cli} server delete web-1") == "high"
    assert rule_id(f"{cli} server list") == "CLI-READ"
    assert level(f"{cli} server list") == "safe"


def test_an_unenumerated_subcommand_of_a_promoted_cli_falls_back_to_the_verb():
    # Promotion is per resource, not per binary: a subcommand nobody wrote a
    # rule for is still classified rather than dropped to safe.
    assert rule_id("gh label delete wontfix") == "CLI-DESTROY"
    assert rule_id("openstack flavor delete m1.small") == "CLI-DESTROY"
    assert rule_id("vault namespace delete acme") == "CLI-DESTROY"
    assert level("velero plugin remove acme/plugin") == "high"


def test_a_cli_nobody_has_enumerated_still_cannot_score_safe():
    assert level("frobctl delete cluster prod") == "high"


# --- the verbs that lie -----------------------------------------------------

def test_vault_kv_delete_is_soft_and_kv_destroy_is_not():
    # `kv delete` marks versions deleted; `kv undelete` brings them back. The
    # generic classifier cannot see that, and scored both as a destroy.
    assert score("vault kv delete secret/db") < score("vault kv destroy secret/db")
    assert one("vault kv delete secret/db")["reversibility"] == "recoverable"
    assert one("vault kv destroy secret/db")["reversibility"] == "irreversible"


def test_openstack_project_delete_leaves_the_resources_running():
    # The trap: the project goes, the servers and volumes in it do not — they
    # keep running and keep billing with nothing left to manage them through.
    assert score("openstack project delete acme") < score("openstack project purge --project acme")
    assert "keep billing" in one("openstack project delete acme")["factors"][0]["why"]


def test_argocd_cluster_rm_does_not_touch_the_cluster():
    assert score("argocd cluster rm https://k8s.internal") < score("argocd app delete api")
    assert one("argocd cluster rm https://k8s.internal")["reversibility"] == "recoverable"


def test_velero_restore_delete_removes_the_record_not_the_restore():
    assert score("velero restore delete r1") < score("velero backup delete daily-1")


def test_gh_api_is_scored_on_the_method_not_the_subcommand():
    # `gh api` is not a destructive verb, so verb classification read
    # `gh api -X DELETE /repos/acme/api` as a write. It deletes the repository.
    assert level("gh api /repos/acme/api") == "safe"
    assert level("gh api -X PATCH /repos/acme/api") == "medium"
    assert level("gh api -X DELETE /repos/acme/api") == "high"


def test_fly_secrets_set_is_a_restart():
    # `secrets set` restarts every machine in the app; `--stage` is the form
    # that does not, and it has to score below the one that does.
    assert score("flyctl secrets set A=b --stage") < score("flyctl secrets set A=b")


# --- per-resource bases, which is the point of promoting a CLI --------------

def test_the_resource_moves_the_score_within_one_cli():
    assert score("openstack server stop web-1") < score("openstack server delete web-1")
    assert score("openstack server delete web-1") < score("openstack volume delete vol-1")
    assert score("flyctl machine destroy 4d8") < score("flyctl apps destroy api")
    assert score("flyctl apps destroy api") < score("flyctl volumes destroy vol_1")
    assert score("gh repo archive acme/api") < score("gh repo delete acme/api")


def test_the_cli_s_own_flags_amplify_and_soften():
    assert score("argocd app sync api --prune") > score("argocd app sync api")
    assert score("argocd app delete api --cascade=false") < score("argocd app delete api")
    assert score("gh pr merge 42 --admin") > score("gh pr merge 42")
    assert score("gh pr merge 42 --auto") < score("gh pr merge 42")
    assert score("vault lease revoke -prefix db/creds/") > score("vault lease revoke db/creds/x")


def test_vault_output_curl_string_sends_nothing():
    # It prints the equivalent curl invocation and makes no request at all,
    # which is vault's dry run under another name.
    assert level("vault delete -output-curl-string secret/db") == "safe"


def test_a_negated_cascade_is_not_a_purge():
    # `--cascade=false` names the purge flag and asks for the opposite.
    assert score("argocd app delete api --cascade=false") < score("argocd app delete api")


# --- --why: the reasoning behind a score, one command away ------------------


def test_every_id_has_a_why_body():
    """The acceptance test from the issue. A rule that can produce a finding
    and prints a blank detail view is worse than one that admits the note is
    missing, so an empty body fails here rather than reaching a user."""
    for rid in rule_ids():
        body = why_text(rid)
        assert body, f"{rid}: no --why body"
        assert body.strip(), f"{rid}: blank --why body"
        assert rid in body, f"{rid}: body does not name the rule"
        assert "MATCHES" in body and "INCIDENT CLASS" in body, f"{rid}: missing a section"


def test_a_rule_scoring_at_all_explains_its_band_and_its_alternative():
    for rid in [r["id"] for r in RULES if r["base"] >= 35]:
        body = why_text(rid)
        assert "WHY THIS BAND" in body, rid
        assert "SAFER" in body, rid


def test_the_derived_view_cannot_disagree_with_the_score():
    """Everything except the incident paragraph is read out of the rule table,
    so the explanation and the scorer are the same facts. A view written by
    hand would drift the first time a base moved."""
    for r in RULES:
        head = why_text(r["id"]).splitlines()[0]
        assert f"base {r['base']}" in head, r["id"]
        assert f"scope: {r['scope']}" in head, r["id"]
        assert r["revert"] in head, r["id"]


def test_a_rule_with_no_incident_note_says_so_rather_than_padding():
    missing = [r["id"] for r in RULES if r["id"] not in INCIDENTS]
    assert missing, "if every rule has a note, delete this test and celebrate"
    body = why_text(missing[0])
    assert "Not written yet" in body
    # ...and still carries the one-line reason, so the view is never useless.
    entry = entry_by_id(missing[0])[1]
    assert entry["why"].split(":")[0][:30] in body


def test_incident_notes_cannot_name_a_rule_that_does_not_exist():
    """The drift the issue was worried about, made into a test: the notes live
    beside the table rather than in it, and this is what keeps them tied."""
    unknown = set(INCIDENTS) - set(rule_ids())
    assert not unknown, f"incident notes for ids that no longer exist: {sorted(unknown)}"


def test_incident_note_coverage_does_not_regress():
    # A floor, not a target. Raise it when notes are added; it exists so a
    # refactor cannot quietly drop them.
    assert len(INCIDENTS) >= 126


def test_incident_notes_are_prose_not_placeholders():
    for rid, note in INCIDENTS.items():
        assert len(note) > 180, f"{rid}: too short to be an incident class"
        assert note.strip().endswith((".", "!")), f"{rid}: unfinished sentence"


def test_why_accepts_an_amplifier_id_in_the_spelling_list_rules_prints():
    """--list-rules prints amplifiers with a leading `+`, so both spellings
    have to resolve — nobody should have to know which half of the table an id
    came from."""
    assert why_text("+FORCE") == why_text("FORCE")
    assert why_text("force") == why_text("FORCE")
    assert "amplifier" in why_text("FORCE")
    assert "softener" in why_text("INTERACTIVE")


def test_an_unknown_id_exits_64_and_suggests_a_near_miss(capsys):
    assert main(["--why", "K8S-DELETE-NAMESPACE"]) == 64
    err = capsys.readouterr().err
    assert "K8S-DELETE-NS" in err


def test_an_id_with_no_near_miss_points_at_list_rules(capsys):
    assert main(["--why", "zzzzzzzz"]) == 64
    assert "--list-rules" in capsys.readouterr().err


def test_a_finding_names_the_rule_so_why_is_discoverable(capsys):
    main(["kubectl delete ns prod"])
    out = capsys.readouterr().out
    assert "scoville --why K8S-DELETE-NS" in out


def test_a_safe_command_keeps_the_pointer_out_of_the_way(capsys):
    main(["ls -la"])
    assert "--why" not in capsys.readouterr().out
    main(["ls -la", "-v"])
    assert "--why READ" in capsys.readouterr().out


def test_json_carries_the_rule_id_on_every_factor_that_has_one(capsys):
    main(["kubectl delete ns prod --all", "--format", "json"])
    result = json.loads(capsys.readouterr().out)
    factors = result["commands"][0]["factors"]
    ids = [f["rule"] for f in factors]
    assert "K8S-DELETE-NS" in ids and "K8S-ALL" in ids and "PROD-HINT" in ids
    # And every id it emits has to resolve, or the pointer is a dead end.
    for rid in ids:
        if rid and rid != "UNKNOWN":
            assert why_text(rid), rid


def test_a_factor_that_is_not_a_rule_carries_no_made_up_id(capsys):
    main(["rm -rf /etc", "--format", "json"])
    result = json.loads(capsys.readouterr().out)
    factors = result["commands"][0]["factors"]
    assert any(f["rule"] == "FS-RM" for f in factors)
    # Path and payload factors are derived, not rules. None, not a fiction.
    assert any(f["rule"] is None for f in factors)
