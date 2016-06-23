#!/usr/bin/env python

import logging
import os
import pwd
import signal
import socket
import subprocess
import sys
import time

import etcd
import jinja2
import six
from six.moves.urllib import parse
import yaml


ENV = 'default'
GLOBALS_PATH = '/etc/mcp/globals/globals.yaml'
NETWORK_TOPOLOGY_FILE = "/etc/mcp/globals/network_topology.yaml"
WORKFLOW_PATH = '/etc/mcp/role/role.yaml'
FILES_DIR = '/etc/mcp/files'

LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
LOG_FORMAT = "%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s"

logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATEFMT)
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


def etcd_path(*path):
    return os.path.join('/mcp', ENV, 'status', 'global', *path)


def set_status_done(service_name, etcd_client):
    key = etcd_path(service_name, "done")
    etcd_client.set(key, "1")


def cmd_str(cmd):
    if isinstance(cmd, six.string_types):
        return cmd
    return " ".join(cmd)


def preexec_fn(user_uid, user_gid, user_home):
    def result():
        os.setgid(user_gid)
        os.setuid(user_uid)
        os.environ["HOME"] = user_home
    return result


def execute_cmd(cmd, user=None):
    LOG.debug("Executing cmd:\n%s", cmd_str(cmd))
    kwargs = {
        "shell": True,
        "stdin": sys.stdin,
        "stdout": sys.stdout,
        "stderr": sys.stderr}
    # Execute as user if `user` param is provided, execute as current user
    # otherwise
    if user:
        LOG.debug('Executing as user %s', user)
        pw_record = pwd.getpwnam(user)
        user_uid = pw_record.pw_uid
        user_gid = pw_record.pw_gid
        user_home = pw_record.pw_dir
        kwargs['preexec_fn'] = preexec_fn(user_uid, user_gid, user_home)
    return subprocess.Popen(cmd_str(cmd), **kwargs)


def str_to_bool(text):
    return text is not None and text.lower() in ['true', 'yes']


def jinja_render_file(path, variables):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(
        os.path.dirname(path)))
    env.filters['bool'] = str_to_bool

    content = env.get_template(os.path.basename(path)).render(variables)

    return content


def jinja_render_cmd(cmd, variables):
    return jinja2.Environment().from_string(cmd).render(variables)


def create_files(files, variables):
    LOG.info("Creating files")
    for config in files:
        file_template = os.path.join(FILES_DIR, config['name'])
        file_path = config['path']

        LOG.debug("Creating %s file from %s template" %
                  (file_path, file_template))
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))

        with open(file_path, 'w') as f:
            rendered_config = jinja_render_file(file_template, variables)
            f.write(rendered_config)

        user = config.get('user')
        if user:
            pw_record = pwd.getpwnam(user)
            user_uid = pw_record.pw_uid
            user_gid = pw_record.pw_gid
            os.chown(file_path, user_uid, user_gid)

        perm = config.get('perm')
        if perm:
            os.chmod(file_path, int(perm, 8))

        LOG.info("File %s has been created", file_path)


def get_etcd_client(etcd_urls):
    etcd_machines = []
    for etcd_machine in etcd_urls.split(","):
        parsed_url = parse.urlparse(etcd_machine)
        etcd_machines.append((parsed_url.hostname, parsed_url.port))

    return etcd.Client(host=tuple(etcd_machines), allow_reconnect=True)


def wait_for_dependencies(dependencies, etcd_client):
    LOG.info('Waiting for dependencies')
    for dep in dependencies:
        LOG.debug("Waiting for \"%s\" dependency", dep)
        path = etcd_path(dep, "done")
        LOG.debug("Checking that path exists %s", path)
        while True:
            if path in etcd_client:
                LOG.debug("Dependency \"%s\" is in \"done\" state", dep)
                break
            LOG.debug("Dependency \"%s\" is not ready yet, retrying", dep)
            time.sleep(5)
    LOG.info("All dependencies are in \"done\" state")


def run_cmd(cmd, variables, user=None):
    rendered_cmd = jinja_render_cmd(cmd, variables)
    LOG.debug('Executing cmd:\n%s', rendered_cmd)
    proc = execute_cmd(rendered_cmd, user)
    proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError("Command exited with code: %d" % proc.returncode)


def run_daemon(cmd, variables, user=None):
    LOG.info("Starting daemon")
    rendered_cmd = jinja_render_cmd(cmd, variables)
    proc = execute_cmd(rendered_cmd, user)

    # add signal handler
    def sig_handler(signum, frame):
        LOG.info("Caught a signal: %d", signum)
        proc.send_signal(signum)
        if signum == signal.SIGHUP:
            time.sleep(5)
            if proc.poll() is None:
                LOG.info("Service restarted")

    signal.signal(signal.SIGHUP, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # wait for 5 sec and check that process is running
    time.sleep(5)
    if proc.poll() is None:
        LOG.info("Daemon started")
        return proc
    proc.communicate()
    raise RuntimeError("Process exited with code: %d" % proc.returncode)


def main():
    LOG.info("Getting global variables from %s", GLOBALS_PATH)
    with open(GLOBALS_PATH) as f:
        variables = yaml.load(f)
        LOG.debug('Global variables:\n%s', variables)

    LOG.info("Getting network topology from %s", NETWORK_TOPOLOGY_FILE)
    with open(NETWORK_TOPOLOGY_FILE) as f:
        topology = yaml.load(f)
    if topology:
        hostname = socket.gethostname()
        if topology.get("network", {}).get(hostname):
            network_info = topology["network"][hostname]
        else:
            ip = socket.gethostbyname(socket.gethostname())
            LOG.debug("Can't find hostname '%s' in network topology file",
                      socket.gethostname())
            network_info = {"private": {"iface": "eth0", "address": ip}}

    LOG.debug("Network information\n%s", yaml.dump(network_info))
    variables["network_topology"] = network_info

    LOG.info("Getting workflow from %s", WORKFLOW_PATH)
    with open(WORKFLOW_PATH) as f:
        workflow = yaml.load(f).get('workflow')
        LOG.debug('Workflow template:\n%s', workflow)

    files = workflow.get('files', [])
    create_files(files, variables)

    etcd_urls = variables.get('etcd_urls')
    if not etcd_urls:
        raise Exception("Etcd urls are not specified")
    LOG.debug("Using the following etcd urls: \"%s\"", etcd_urls)

    etcd_client = get_etcd_client(etcd_urls)

    global ENV
    ENV = variables.get('environment', 'default')

    dependencies = workflow.get('dependencies', [])
    wait_for_dependencies(dependencies, etcd_client)

    pre_commands = workflow.get('pre', [])
    LOG.info('Runnning pre commands')
    for cmd in pre_commands:
        run_cmd(cmd.get('command'), variables, cmd.get('user'))

    daemon = workflow.get('daemon')
    if daemon:
        proc = run_daemon(daemon.get('command'), variables, daemon.get('user'))

    job = workflow.get('job')
    if job:
        LOG.info('Running single command')
        run_cmd(job.get('command'), variables, job.get('user'))

    LOG.info('Running post commands')
    post_commands = workflow.get('post', [])
    for cmd in post_commands:
        run_cmd(cmd.get('command'), variables, cmd.get('user'))

    set_status_done(workflow.get('name'), etcd_client)

    if daemon:
        code = proc.wait()
        LOG.info("Process exited with code %d", code)
        sys.exit(code)


if __name__ == "__main__":
    main()
