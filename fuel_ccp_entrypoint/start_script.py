#!/usr/bin/env python


import argparse
import functools
import logging
import os
import os.path
import pwd
import signal
import socket
import subprocess
import sys
import time

import etcd
import jinja2
import json
import netifaces
import pykube
import requests
import six


VARIABLES = {}
GLOBALS_PATH = '/etc/ccp/globals/globals.json'
META_FILE = "/etc/ccp/meta/meta.json"
CACERT = "/opt/ccp/etc/tls/ca.pem"
WORKFLOW_PATH_TEMPLATE = '/etc/ccp/role/%s.json'
FILES_DIR = '/etc/ccp/files'
EXPORTS_DIR = '/etc/ccp/exports'

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

    if meta_info.get("host-net"):
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
        os.environ["OS_INTERFACE"] = "internal"
        os.environ["OS_PROJECT_DOMAIN_NAME"] = 'default'
        os.environ["OS_USER_DOMAIN_NAME"] = "default"
        os.environ["OS_PASSWORD"] = VARIABLES['openstack']['user_password']
        os.environ["OS_USERNAME"] = VARIABLES['openstack']['user_name']
        os.environ["OS_PROJECT_NAME"] = VARIABLES['openstack']['project_name']
        scheme = 'http'
        if VARIABLES['security']['tls']['enabled']:
            scheme = 'https'
            # Pass CA cert for using by client, because it's not possible to
            # specify insecure via environment.
            if not os.path.isfile(fname):
                with open(CACERT, 'w') as tmp_cert:
                    tmp_cert.write(VARIABLES['security']['tls']['ca_cert'])
            os.environ["OS_CACERT"] = CACERT
        os.environ["OS_AUTH_URL"] = '%s://%s/v3' % (scheme, address(
            'keystone', VARIABLES['keystone']['admin_port']))
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
    for prefix in ["openstack ", "neutron ", "murano "]:
        if cmd.startswith(prefix):
            kwargs['preexec_fn'] = openstackclient_preexec_fn()
            break
    # Execute as user if `user` param is provided, execute as current user
    # otherwise
    else:
        if user:
            LOG.debug('Executing as user %s', user)
            pw_record = pwd.getpwnam(user)
            user_uid = pw_record.pw_uid
            user_gid = pw_record.pw_gid
            user_home = pw_record.pw_dir
            kwargs['preexec_fn'] = preexec_fn(user_uid, user_gid, user_home)
    return subprocess.Popen(cmd_str(cmd), **kwargs)


def get_ingress_host(ingress_name):
    return '.'.join((ingress_name, VARIABLES['ingress']['domain']))


def address(service, port=None, external=False, with_scheme=False):
    addr = None
    scheme = 'http'
    TLS_SERVICES = "keystone,glance,glance,horizon,nova,neutron,cinder,heat"
    if ((VARIABLES['security']['tls']['enabled'] and
         service.split('-')[0] in TLS_SERVICES.split(','))):
        scheme = 'https'
    if external:
        if not port:
            raise RuntimeError('Port config is required for external address')
        if VARIABLES['ingress']['enabled'] and port.get('ingress'):
            scheme = 'https'
            addr = "%s:%s" % (get_ingress_host(port['ingress']),
                              VARIABLES['ingress']['port'])
        elif port.get('node'):
            addr = '%s:%s' % (VARIABLES['k8s_external_ip'], port['node'])

    if addr is None:
        addr = '.'.join((service, VARIABLES['namespace'], 'svc',
                         VARIABLES['cluster_domain']))
        if port:
            addr = '%s:%s' % (addr, port['cont'])

    if with_scheme:
        addr = "%s://%s" % (scheme, addr)

    return addr


def j2raise(msg):
    raise AssertionError(msg)


def jinja_render_file(path, lookup_paths=None):
    file_loaders = [jinja2.FileSystemLoader(os.path.dirname(path))]
    for p in lookup_paths:
        file_loaders.append(jinja2.FileSystemLoader(p))
    env = jinja2.Environment(loader=jinja2.ChoiceLoader(loaders=file_loaders))
    env.globals['address'] = address
    env.globals['raise_exception'] = j2raise
    env.filters['gethostbyname'] = socket.gethostbyname
    content = env.get_template(os.path.basename(path)).render(VARIABLES)

    return content


def jinja_render_cmd(cmd):
    env = jinja2.Environment()
    env.globals['address'] = address
    env.filters['gethostbyname'] = socket.gethostbyname
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
            rendered_config = jinja_render_file(file_template, [EXPORTS_DIR])
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
    if VARIABLES["security"]["tls"]["enabled"]:
        LOG.debug("TLS is enabled for etcd, using encrypted connectivity")
        scheme = "https"
        ca_cert = CACERT
    else:
        scheme = "http"
        ca_cert = None

    etcd_machines = []
    # if it's etcd container use local address because container is not
    # accessible via service due failed readiness check
    if VARIABLES["role_name"] in ["etcd", "etcd-leader-elector",
                                  "etcd-watcher"]:
        if VARIABLES["security"]["tls"]["enabled"]:
            # If it's etcd container, connectivity goes over IP address, thus
            # TLS connection will fail. Need to reuse non-TLS
            # https://github.com/coreos/etcd/issues/4311
            scheme = "http"
            ca_cert = None
            etcd_address = '127.0.0.1'
        else:
            etcd_address = VARIABLES["network_topology"]["private"]["address"]
        etcd_machines.append(
            (etcd_address, VARIABLES["etcd"]["client_port"]['cont']))
    else:
        etcd_machines.append(
            (address('etcd'), VARIABLES["etcd"]["client_port"]['cont'])
        )
    etcd_machines_str = " ".join(["%s:%d" % (h, p) for h, p in etcd_machines])
    LOG.debug("Using the following etcd urls: \"%s\"", etcd_machines_str)

    return etcd.Client(host=tuple(etcd_machines), allow_reconnect=True,
                       read_timeout=2, protocol=scheme, ca_cert=ca_cert)


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


def get_pykube_client():
    os.environ['KUBERNETES_SERVICE_HOST'] = 'kubernetes.default'
    config = pykube.KubeConfig.from_service_account()
    return pykube.HTTPClient(config)


def _reload_obj(obj, updated_dict):
    obj.reload()
    obj.obj = updated_dict


def get_pykube_object(object_dict, namespace, client):
    obj_class = getattr(pykube, object_dict["kind"], None)
    if obj_class is None:
        raise RuntimeError('"%s" object is not supported, skipping.'
                           % object_dict['kind'])

    if not object_dict['kind'] == 'Namespace':
        object_dict['metadata']['namespace'] = namespace

    return obj_class(client, object_dict)

UPDATABLE_OBJECTS = ('ConfigMap', 'Deployment', 'Service', 'Ingress')


def process_pykube_object(object_dict, namespace, client):
    LOG.debug("Deploying %s: \"%s\"",
              object_dict["kind"], object_dict["metadata"]["name"])

    obj = get_pykube_object(object_dict, namespace, client)

    if obj.exists():
        LOG.debug('%s "%s" already exists', object_dict['kind'],
                  object_dict['metadata']['name'])
        if object_dict['kind'] in UPDATABLE_OBJECTS:
            if object_dict['kind'] == 'Service':
                # Reload object and merge new and old fields
                _reload_obj(obj, object_dict)
            obj.update()
            LOG.debug('%s "%s" has been updated', object_dict['kind'],
                      object_dict['metadata']['name'])
    else:
        obj.create()
        LOG.debug('%s "%s" has been created', object_dict['kind'],
                  object_dict['metadata']['name'])
    return obj


def wait_for_deployment(obj):
    while True:
        generation = obj.obj['metadata']['generation']
        observed_generation = obj.obj['status']['observedGeneration']
        if observed_generation >= generation:
            break
        LOG.info("Waiting for deployment %s to move to new generation")
        time.sleep(4.2)
        obj.reload()

    while True:
        desired = obj.obj['spec']['replicas']
        status = obj.obj['status']
        updated = status.get('updatedReplicas', 0)
        available = status.get('availableReplicas', 0)
        current = status.get('replicas', 0)
        if desired == updated == available == current:
            break
        LOG.info("Waiting for deployment %s: desired=%s, updated=%s,"
                 " available=%s, current=%s",
                 obj.obj['metadata']['name'],
                 desired, updated, available, current)
        time.sleep(4.2)
        obj.reload()


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
    if os.path.exists(META_FILE):
        LOG.info("Getting meta information from %s", META_FILE)
        with open(META_FILE) as f:
            meta_info = json.load(f)
    else:
        meta_info = {}
    variables['role_name'] = role_name
    LOG.info("Get CCP environment variables")
    variables['node_name'] = os.environ['CCP_NODE_NAME']
    variables['pod_name'] = os.environ['CCP_POD_NAME']
    LOG.debug("Creating network topology ")
    variables["network_topology"] = create_network_topology(meta_info,
                                                            variables)
    return variables


def _get_ca_certificate():
    name = CACERT
    if not os.path.isfile(name):
        with open(CACERT, 'w') as f:
            f.write(VARIABLES['security']['tls']['ca_cert'])
            LOG.info("CA certificated saved to %s", CACERT)
    else:
        LOG.info("CA file exists, not overwriting it")


def main():
    action_parser = argparse.ArgumentParser(add_help=False)
    action_parser.add_argument("action")
    parser = argparse.ArgumentParser(parents=[action_parser])
    parser.add_argument("role")
    args = parser.parse_args(sys.argv[1:])

    global VARIABLES
    VARIABLES = get_variables(args.role)
    LOG.debug('Global variables:\n%s', VARIABLES)

    if VARIABLES["security"]["tls"]["enabled"]:
        _get_ca_certificate()
    if args.action == "provision":
        do_provision(args.role)
    elif args.action == "status":
        do_status(args.role)
    else:
        LOG.error("Action %s is not supported", args.action)


def run_probe(probe):
    if probe["type"] == "exec":
        run_cmd(probe["command"])
    elif probe["type"] == "httpGet":
        scheme = 'http'
        verify = True
        if VARIABLES['security']['tls']['enabled']:
            scheme = 'https'
            # disable SSL check for probe request
            verify = False
        url = "{}://{}:{}{}".format(
            scheme,
            VARIABLES["network_topology"]["private"]["address"],
            probe["port"],
            probe.get("path", "/"))
        resp = requests.get(url, verify=verify)
        resp.raise_for_status()


def do_status(role_name):
    workflow = get_workflow(role_name)
    service_name = workflow["name"]
    # check local status in etcd
    local_dep = "%s:local" % service_name
    if not check_is_done(local_dep):
        LOG.info("Service is not done")
        sys.exit(1)
    LOG.info("Service in done state")
    # launch readiness probe
    readiness_probe = workflow.get("readiness")
    if readiness_probe:
        if not isinstance(readiness_probe, dict):
            readiness_probe = {"type": "exec", "command": readiness_probe}
        run_probe(readiness_probe)
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
    roll = workflow.get("roll")
    kill = workflow.get("kill")
    if job:
        execute_job(workflow, job)
    elif daemon:
        execute_daemon(workflow, daemon)
    elif roll is not None:
        execute_roll(workflow, roll)
    elif kill is not None:
        execute_kill(workflow, kill)
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


def execute_roll(workflow, roll):
    LOG.info("Running rolling upgrade of service %s", workflow["name"])
    namespace = VARIABLES["namespace"]
    client = get_pykube_client()
    deployments = []
    for object_dict in roll:
        obj = process_pykube_object(object_dict, namespace, client)
        if object_dict['kind'] == 'Deployment':
            deployments.append(obj)
    for obj in deployments:
        wait_for_deployment(obj)
    set_status_ready(workflow["name"])
    sys.exit(0)


def execute_kill(workflow, kill):
    LOG.info("Killing deployments for service %s", workflow["name"])
    namespace = VARIABLES["namespace"]
    client = get_pykube_client()
    objs = []
    for object_dict in kill:
        if object_dict['kind'] != 'Deployment':
            LOG.warn("Don't know how to handle %s, skipping",
                     object_dict['kind'])
            continue
        obj = get_pykube_object(object_dict, namespace, client)
        obj.reload()
        obj.obj['spec']['replicas'] = 0
        obj.update()
        objs.append(obj)
    for obj in objs:
        wait_for_deployment(obj)
    set_status_ready(workflow["name"])
    sys.exit(0)

if __name__ == "__main__":
    main()
