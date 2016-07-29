#!/usr/bin/env python

import functools
import logging
import os
import pwd
import signal
import subprocess
import sys
import time

import etcd
import jinja2
import netifaces
import six
from six.moves.urllib import parse
import yaml


VARIABLES = {}
GLOBALS_PATH = '/etc/mcp/globals/globals.yaml'
META_FILE = "/etc/mcp/meta/meta.yaml"
WORKFLOW_PATH_TEMPLATE = '/etc/mcp/role/%s.yaml'
FILES_DIR = '/etc/mcp/files'

LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
LOG_FORMAT = "%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s"

logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATEFMT)
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


def retry(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        attempts = VARIABLES.get('etcd_connection_attempts', 10)
        delay = VARIABLES.get('etcd_connection_delay', 5)
        while attempts > 1:
            try:
                return f(*args, **kwargs)
            except etcd.EtcdException as e:
                LOG.warning('Etcd is not ready: %s', str(e))
                LOG.warning('Retrying in %d seconds...', delay)
                time.sleep(delay)
                attempts -= 1
        return f(*args, **kwargs)
    return wrap


def get_ip_address(iface):
    """Get IP address of the interface connected to the network.

    If there is no such an interface, then localhost is returned.
    """

    if iface not in netifaces.interfaces():
        LOG.warning("Can't find interface '%s' in the host list of interfaces",
                    iface)
        return '127.0.0.1'

    address_family = netifaces.AF_INET

    if address_family not in netifaces.ifaddresses(iface):
        LOG.warning("Interface '%s' doesnt configured with ipv4 address",
                    iface)
        return '127.0.0.1'

    for ifaddress in netifaces.ifaddresses(iface)[address_family]:
        if 'addr' in ifaddress:
            return ifaddress['addr']
        else:
            LOG.warning("Can't find ip addr for interface '%s'", iface)
            return '127.0.0.1'


def create_network_topology(meta_info):
    """Create a network topology config.

       These config could be used in jinja2 templates to fetch needed variables
       Example:
       {{ network_topology["private"]["address"] }}
       {{ network_topology["public"]["iface"] }}
    """

    if meta_info["host-net"]:
        LOG.debug("Found 'host-net' flag, trying to fetch host network")
        priv_iface = VARIABLES["private_interface"]
        pub_iface = VARIABLES["public_interface"]
        network_info = {"private": {"iface": priv_iface,
                                    "address": get_ip_address(priv_iface)},
                        "public": {"iface": pub_iface,
                                   "address": get_ip_address(pub_iface)}}
    else:
        LOG.debug("Can't find 'host-net' flag, fetching ip only from eth0")
        network_info = {"private": {"iface": "eth0",
                                    "address": get_ip_address("eth0")},
                        "public": {"iface": "eth0",
                                   "address": get_ip_address("eth0")}}
    LOG.debug("Network information\n%s", yaml.dump(network_info))
    return network_info


def etcd_path(*path):
    namespace = VARIABLES.get('namespace', '')
    return os.path.join('/mcp', namespace, 'status', 'global', *path)


@retry
def set_status_done(service_name, etcd_client):
    key = etcd_path(service_name, "done")
    etcd_client.set(key, "1")
    LOG.info('Status for "%s" was set to "done"', service_name)


def check_is_done(service_name):
    key = etcd_path(service_name, "done")
    etcd_client = get_etcd_client()
    return key in etcd_client


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


def openstackclient_preexec_fn():
    def result():
        os.environ["OS_IDENTITY_API_VERSION"] = "3"
        os.environ["OS_DOMAIN_NAME"] = 'default'
        os.environ["OS_PASSWORD"] = VARIABLES['openstack_user_password']
        os.environ["OS_USERNAME"] = VARIABLES['openstack_user_name']
        os.environ["OS_PROJECT_NAME"] = VARIABLES['openstack_project_name']
        os.environ["OS_AUTH_URL"] = 'http://keystone:%s/v3' % VARIABLES[
            'keystone_admin_port']
    return result


def execute_cmd(cmd, user=None):
    LOG.debug("Executing cmd:\n%s", cmd_str(cmd))
    kwargs = {
        "shell": True,
        "stdin": sys.stdin,
        "stdout": sys.stdout,
        "stderr": sys.stderr}
    # If openstackclient command is being executed, appropriate environment
    # variables will be set
    if cmd.startswith('openstack '):
        kwargs['preexec_fn'] = openstackclient_preexec_fn()
    # Execute as user if `user` param is provided, execute as current user
    # otherwise
    elif user:
        LOG.debug('Executing as user %s', user)
        pw_record = pwd.getpwnam(user)
        user_uid = pw_record.pw_uid
        user_gid = pw_record.pw_gid
        user_home = pw_record.pw_dir
        kwargs['preexec_fn'] = preexec_fn(user_uid, user_gid, user_home)
    return subprocess.Popen(cmd_str(cmd), **kwargs)


def str_to_bool(text):
    return text is not None and text.lower() in ['true', 'yes']


def jinja_render_file(path):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(
        os.path.dirname(path)))
    env.filters['bool'] = str_to_bool

    content = env.get_template(os.path.basename(path)).render(VARIABLES)

    return content


def jinja_render_cmd(cmd):
    return jinja2.Environment().from_string(cmd).render(VARIABLES)


def create_files(files):
    LOG.info("Creating files")
    for config in files:
        file_template = os.path.join(FILES_DIR, config['name'])
        file_path = config['path']

        LOG.debug("Creating %s file from %s template" %
                  (file_path, file_template))
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))

        with open(file_path, 'w') as f:
            rendered_config = jinja_render_file(file_template)
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


@retry
def get_etcd_client():
    etcd_urls = VARIABLES.get("etcd_urls")
    if not etcd_urls:
        raise Exception("Etcd urls are not specified")
    LOG.debug("Using the following etcd urls: \"%s\"", etcd_urls)
    etcd_machines = []
    for etcd_machine in etcd_urls.split(","):
        parsed_url = parse.urlparse(etcd_machine)
        etcd_machines.append((parsed_url.hostname, parsed_url.port))

    return etcd.Client(host=tuple(etcd_machines), allow_reconnect=True,
                       read_timeout=2)


@retry
def check_dependence(dep, etcd_client):
    LOG.debug("Waiting for \"%s\" dependency", dep)
    path = etcd_path(dep, "done")
    LOG.debug("Checking that path exists %s", path)
    while True:
        if path in etcd_client:
            LOG.debug("Dependency \"%s\" is in \"done\" state", dep)
            break
        LOG.debug("Dependency \"%s\" is not ready yet, retrying", dep)
        time.sleep(5)


def wait_for_dependencies(dependencies, etcd_client):
    LOG.info('Waiting for dependencies')
    for dep in dependencies:
        check_dependence(dep, etcd_client)


def run_cmd(cmd, user=None):
    rendered_cmd = jinja_render_cmd(cmd)
    proc = execute_cmd(rendered_cmd, user)
    proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError("Command exited with code: %d" % proc.returncode)


def run_daemon(cmd, user=None):
    LOG.info("Starting daemon")
    rendered_cmd = jinja_render_cmd(cmd)
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


def get_workflow(role_name):
    workflow_path = WORKFLOW_PATH_TEMPLATE % role_name
    LOG.info("Getting workflow from %s", workflow_path)
    with open(workflow_path) as f:
        workflow = yaml.load(f).get('workflow')
    LOG.debug('Workflow template:\n%s', workflow)
    return workflow


def setup_variables(role_name):
    global VARIABLES
    LOG.info("Getting global variables from %s", GLOBALS_PATH)
    with open(GLOBALS_PATH) as f:
        VARIABLES = yaml.load(f)
    with open(META_FILE) as f:
        meta_info = yaml.load(f)
    VARIABLES['role_name'] = role_name
    LOG.debug('Global variables:\n%s', VARIABLES)
    LOG.debug("Getting meta info from %s", META_FILE)
    LOG.debug("Creating network topology configuration")
    VARIABLES["network_topology"] = create_network_topology(meta_info)


def main():
    argv_len = len(sys.argv)
    if argv_len == 3:
        action = sys.argv[1]
        role_name = sys.argv[2]
    elif argv_len == 2:
        action = "provision"
        role_name = sys.argv[1]
    else:
        LOG.error("wrong arguments")
        sys.exit(1)

    setup_variables(role_name)

    if action == "provision":
        do_provision(role_name)
    elif action == "status":
        do_status(role_name)
    else:
        LOG.error("Action %s is not supported", action)
        sys.exit(1)


def do_status(role_name):
    workflow = get_workflow(role_name)
    if not check_is_done(workflow.get("name")):
        sys.exit(1)


def do_provision(role_name):
    workflow = get_workflow(role_name)
    files = workflow.get('files', [])
    create_files(files)

    etcd_client = None

    dependencies = workflow.get('dependencies')
    if dependencies:
        etcd_client = get_etcd_client()
        wait_for_dependencies(dependencies, etcd_client)

    pre_commands = workflow.get('pre', [])
    LOG.info('Runnning pre commands')
    for cmd in pre_commands:
        run_cmd(cmd.get('command'), cmd.get('user'))

    daemon = workflow.get('daemon')
    if daemon:
        proc = run_daemon(daemon.get('command'), daemon.get('user'))

    job = workflow.get('job')
    if job:
        LOG.info('Running single command')
        run_cmd(job.get('command'), job.get('user'))

    LOG.info('Running post commands')
    post_commands = workflow.get('post', [])
    for cmd in post_commands:
        run_cmd(cmd.get('command'), cmd.get('user'))

    set_status_done(
        workflow.get('name'), etcd_client or get_etcd_client())

    if daemon:
        code = proc.wait()
        LOG.info("Process exited with code %d", code)
        sys.exit(code)


if __name__ == "__main__":
    main()
