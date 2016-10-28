#!/usr/bin/env python


import argparse
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
import json
import netifaces
import six


VARIABLES = {}
GLOBALS_PATH = '/etc/ccp/globals/globals.json'
META_FILE = "/etc/ccp/meta/meta.json"
WORKFLOW_PATH_TEMPLATE = '/etc/ccp/role/%s.json'
FILES_DIR = '/etc/ccp/files'

LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
LOG_FORMAT = "%(asctime)s.%(msecs)03d - %(name)s - %(levelname)s - %(message)s"

logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATEFMT)
LOG = logging.getLogger(__name__)
LOG.setLevel(logging.DEBUG)


class ProcessException(Exception):
    def __init__(self, exit_code):
        self.exit_code = exit_code
        self.msg = "Command exited with code %d" % self.exit_code
        super(ProcessException, self).__init__(self.msg)


def retry(f):
    @functools.wraps(f)
    def wrap(*args, **kwargs):
        attempts = VARIABLES['etcd']['connection_attempts']
        delay = VARIABLES['etcd']['connection_delay']
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


def create_network_topology(meta_info, variables):
    """Create a network topology config.

       These config could be used in jinja2 templates to fetch needed variables
       Example:
       {{ network_topology["private"]["address"] }}
       {{ network_topology["public"]["iface"] }}
    """

    if meta_info["host-net"]:
        LOG.debug("Found 'host-net' flag, trying to fetch host network")
        priv_iface = variables["private_interface"]
        pub_iface = variables["public_interface"]
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
    LOG.debug("Network information\n%s", network_info)
    return network_info


def etcd_path(*path):
    namespace = VARIABLES.get('namespace', '')
    return os.path.join('/ccp', namespace, 'status', *path)


def set_status_done(service_name):
    return _set_status(service_name, "done")


def set_status_ready(service_name, ttl=None):
    return _set_status(service_name, "ready", ttl=ttl)


@retry
def _set_status(service_name, status, ttl=None):
    etcd_client = get_etcd_client()
    for dep_type in ['global', VARIABLES['node_name']]:
        key = etcd_path(dep_type, service_name, status)
        etcd_client.set(key, "1", ttl=ttl)
        LOG.info('Status for "%s" was set to "%s"',
                 os.path.join(dep_type, service_name), status)


def check_is_done(dep):
    return _check_status(dep, "done")


def check_is_ready(dep, etcd_client=None):
    return _check_status(dep, "ready", etcd_client)


@retry
def _check_status(dep, status, etcd_client=None):
    if not etcd_client:
        etcd_client = get_etcd_client()
    dep_name, _, dep_type = dep.partition(":")
    dep_type = VARIABLES['node_name'] if dep_type == 'local' else 'global'
    key = etcd_path(dep_type, dep_name, status)
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
        os.environ["OS_PROJECT_DOMAIN_NAME"] = 'default'
        os.environ["OS_PASSWORD"] = VARIABLES['openstack']['user_password']
        os.environ["OS_USERNAME"] = VARIABLES['openstack']['user_name']
        os.environ["OS_PROJECT_NAME"] = VARIABLES['openstack']['project_name']
        os.environ["OS_AUTH_URL"] = 'http://%s/v3' % address(
            'keystone', VARIABLES['keystone']['admin_port'])
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


def get_ingress_host(ingress_name):
    return '.'.join((
        ingress_name, VARIABLES['namespace'], VARIABLES['ingress']['domain']))


def address(service, port=None, external=False, multiple=False, delimiter=','):
    addr = None
    if external:
        if not port:
            raise RuntimeError('Port config is required for external address')
        if VARIABLES['ingress']['enabled'] and port.get('ingress'):
            addr = get_ingress_host(port['ingress'])
        elif port.get('node'):
            addr = '%s:%s' % (VARIABLES['k8s_external_ip'], port['node'])

    if addr is None:
        addr = '%s.%s' % (service, VARIABLES['namespace'])
        if port:
            addr = '%s:%s' % (addr, port['cont'])
        if multiple:
            replicas = VARIABLES['replicas'] or 1
            urls = ['%s-%i.%s' % (service, pod_number, addr)
                    for pod_number in range(replicas)]
            addr = delimiter.join(urls)

    return addr


def jinja_render_file(path):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(
        os.path.dirname(path)))
    env.globals['address'] = address
    content = env.get_template(os.path.basename(path)).render(VARIABLES)

    return content


def jinja_render_cmd(cmd):
    env = jinja2.Environment()
    env.globals['address'] = address
    return env.from_string(cmd).render(VARIABLES)


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
    etcd_machines = []
    # if it's etcd container use local address because container is not
    # accessible via service due failed readiness check
    if VARIABLES["role_name"] == "etcd":
        etcd_machines.append(
            (VARIABLES["network_topology"]["private"]["address"],
             VARIABLES["etcd"]["client_port"]['cont']))
    else:
        etcd_machines.append(
            (address('etcd'), VARIABLES["etcd"]["client_port"]['cont'])
        )

    etcd_machines_str = " ".join(["%s:%d" % (h, p) for h, p in etcd_machines])
    LOG.debug("Using the following etcd urls: \"%s\"", etcd_machines_str)

    return etcd.Client(host=tuple(etcd_machines), allow_reconnect=True,
                       read_timeout=2)


def check_dependence(dep, etcd_client):
    LOG.debug("Waiting for \"%s\" dependency", dep)
    while True:
        if check_is_ready(dep, etcd_client):
            LOG.debug("Dependency \"%s\" is in \"ready\" state", dep)
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
        raise ProcessException(proc.returncode)


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
        workflow = json.load(f).get('workflow')
    LOG.debug('Workflow template:\n%s', workflow)
    return workflow


def get_variables(role_name):
    LOG.info("Getting global variables from %s", GLOBALS_PATH)
    with open(GLOBALS_PATH) as f:
        variables = json.load(f)
    LOG.info("Getting meta information from %s", META_FILE)
    with open(META_FILE) as f:
        meta_info = json.load(f)
    variables['role_name'] = role_name
    variables['replicas'] = meta_info['replicas']
    LOG.info("Get CCP environment variables")
    if os.environ.get('CCP_NODE_NAME'):
        variables['node_name'] = os.environ['CCP_NODE_NAME']
    LOG.debug("Getting meta info from %s", META_FILE)
    LOG.debug("Creating network topology configuration")
    variables["network_topology"] = create_network_topology(meta_info,
                                                            variables)
    return variables


def main():
    action_parser = argparse.ArgumentParser(add_help=False)
    action_parser.add_argument("action")
    parser = argparse.ArgumentParser(parents=[action_parser])
    parser.add_argument("role")
    args = parser.parse_args(sys.argv[1:])

    global VARIABLES
    VARIABLES = get_variables(args.role)
    LOG.debug('Global variables:\n%s', VARIABLES)

    if args.action == "provision":
        do_provision(args.role)
    elif args.action == "status":
        do_status(args.role)
    else:
        LOG.error("Action %s is not supported", args.action)


def do_status(role_name):
    workflow = get_workflow(role_name)
    service_name = workflow["name"]
    # check status in etcd
    if not check_is_done(service_name):
        LOG.info("Service is not done")
        sys.exit(1)
    LOG.info("Service in done state")
    # launch readiness command
    readiness_cmd = workflow.get("readiness")
    if readiness_cmd:
        run_cmd(readiness_cmd)
    # set ready in etcd
    # ttl 20 because readiness check runs each 10 sec
    set_status_ready(service_name, ttl=20)


def do_provision(role_name):
    workflow = get_workflow(role_name)
    files = workflow.get('files', [])
    create_files(files)

    dependencies = workflow.get('dependencies')
    if dependencies:
        etcd_client = get_etcd_client()
        wait_for_dependencies(dependencies, etcd_client)

    job = workflow.get("job")
    daemon = workflow.get("daemon")
    if job:
        execute_job(workflow, job)
    elif daemon:
        execute_daemon(workflow, daemon)
    else:
        LOG.error("Job or daemon is not specified in workflow")
        sys.exit(1)


def execute_daemon(workflow, daemon):
    pre_commands = workflow.get('pre', [])
    LOG.info('Running pre commands')
    for cmd in pre_commands:
        run_cmd(cmd.get('command'), cmd.get('user'))

    proc = run_daemon(daemon.get('command'), daemon.get('user'))

    LOG.info('Running post commands')
    post_commands = workflow.get('post', [])
    for cmd in post_commands:
        run_cmd(cmd.get('command'), cmd.get('user'))

    set_status_done(workflow["name"])

    code = proc.wait()
    LOG.info("Process exited with code %d", code)
    sys.exit(code)


def execute_job(workflow, job):
    LOG.info('Running single command')
    try:
        run_cmd(job.get('command'), job.get('user'))
    except ProcessException as ex:
        LOG.error("Job execution failed")
        sys.exit(ex.exit_code)
    set_status_ready(workflow["name"])
    sys.exit(0)


if __name__ == "__main__":
    main()
