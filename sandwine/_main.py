# sandwine - runs Windows applications in a sandboxed environment using Wine and Bubblewrap (Conty from Wish, without the compression)

# Command-line interface to run Windows applications in a sandboxed environment # using Wine and Bubblewrap. 
# Modular and extensible. Uses the ArgumentParser for command-line argument
# handling, and various helper functions and classes for specific functionalities such as X11 handling,
# mount point management, and environment variable setup. The main function orchestrates the execution
# of the sandboxed application.


# The script starts by parsing command-line arguments to configure the sandbox environment. It then sets up
# the necessary mount points, environment variables, and other configurations. The main function handles
# the execution of the sandboxed application using subprocess.call, ensuring that the environment is
# properly isolated and configured before execution.

import logging
import os
import random
import shlex
import signal
import subprocess
import sys
from argparse import ArgumentParser, RawTextHelpFormatter
from contextlib import nullcontext
from dataclasses import dataclass
from enum import Enum, auto
from importlib.metadata import metadata
from operator import attrgetter, itemgetter
from textwrap import dedent
from typing import Optional

import coloredlogs

from sandwine._x11 import X11Display, X11Mode, create_x11_context, detect_and_require_nested_x11

_logger = logging.getLogger(__name__)


# Enum to define access modes for mount points
class AccessMode(Enum):
    READ_ONLY = 'ro'
    READ_WRITE = 'rw'


# Enum to define different mount modes
class MountMode(Enum):
    DEVTMPFS = auto()
    BIND_RO = auto()
    BIND_RW = auto()
    BIND_DEV = auto()
    TMPFS = auto()
    PROC = auto()


# Function to parse command-line arguments
def parse_command_line(args):
    distribution = metadata('sandwine')

    usage = dedent('''\
        usage: sandwine [OPTIONS] [--] PROGRAM [ARG ..]
           or: sandwine [OPTIONS] --configure
           or: sandwine --help
           or: sandwine --version
    ''')[len('usage: '):]

    parser = ArgumentParser(
        prog='sandwine',
        usage=usage,
        description=distribution['Summary'],
        formatter_class=RawTextHelpFormatter,
        epilog=dedent("""\
        Software is opensource.
        Credit to Sebastian Pipping <sebastian@pipping.org>.

        Orignal code from https://github.com/hartwork/sandwine, same functionality dirty codebase
    """),
    )

    parser.add_argument('--version', action='version', version=distribution['Version'])

    add_positional_arguments(parser)
    add_x11_arguments(parser)
    add_networking_arguments(parser)
    add_sound_arguments(parser)
    add_mount_arguments(parser)
    add_general_operation_arguments(parser)

    return parser.parse_args(args)


# Function to add positional arguments to the argument parser
def add_positional_arguments(parser):
    program = parser.add_argument_group('positional arguments')
    program.add_argument('argv_0', metavar='PROGRAM', nargs='?', help='command to run')
    program.add_argument('argv_1_plus', metavar='ARG', nargs='*', help='arguments to pass to PROGRAM')


# Function to add X11-related arguments to the argument parser
def add_x11_arguments(parser):
    x11_args = parser.add_argument_group('X11 arguments')
    x11_args.set_defaults(x11=X11Mode.NONE)
    x11_args.add_argument('--x11', dest='x11', action='store_const', const=X11Mode.AUTO, help=dedent('''\
        enable nested X11 using X2Go nxagent or Xephyr or Xnest
        but not Xvfb and not Xpra (default: X11 disabled)'''))
    x11_args.add_argument('--nxagent', dest='x11', action='store_const', const=X11Mode.NXAGENT, help='enable nested X11 using X2Go nxagent (default: X11 disabled)')
    x11_args.add_argument('--xephyr', dest='x11', action='store_const', const=X11Mode.XEPHYR, help='enable nested X11 using Xephyr (default: X11 disabled)')
    x11_args.add_argument('--xnest', dest='x11', action='store_const', const=X11Mode.XNEST, help='enable nested X11 using Xnest (default: X11 disabled)')
    x11_args.add_argument('--xpra', dest='x11', action='store_const', const=X11Mode.XPRA, help='enable nested X11 using Xpra (EXPERIMENTAL, CAREFUL!) (default: X11 disabled)')
    x11_args.add_argument('--xvfb', dest='x11', action='store_const', const=X11Mode.XVFB, help='enable nested X11 using Xvfb (default: X11 disabled)')
    x11_args.add_argument('--host-x11-danger-danger', dest='x11', action='store_const', const=X11Mode.HOST, help='enable use of host X11 (CAREFUL!) (default: X11 disabled)')


# Function to add networking-related arguments to the argument parser
def add_networking_arguments(parser):
    networking = parser.add_argument_group('networking arguments')
    networking.add_argument('--network', action='store_true', help='enable networking (default: networking disabled)')


# Function to add sound-related arguments to the argument parser
def add_sound_arguments(parser):
    sound = parser.add_argument_group('sound arguments')
    sound.add_argument('--pulseaudio', action='store_true', help='enable sound using PulseAudio (default: sound disabled)')


# Function to add mount-related arguments to the argument parser
def add_mount_arguments(parser):
    mount = parser.add_argument_group('mount arguments')
    mount.add_argument('--dotwine', metavar='PATH:{ro,rw}', help='use PATH for ~/.wine/ (default: use tmpfs, empty and non-persistent)')
    mount.add_argument('--pass', dest='extra_binds', default=[], action='append', metavar='PATH:{ro,rw}', help='bind mount host PATH on PATH (CAREFUL!)')


# Function to add general operation-related arguments to the argument parser
def add_general_operation_arguments(parser):
    general = parser.add_argument_group('general operation arguments')
    general.add_argument('--configure', action='store_true', help='enforce running winecfg before start of PROGRAM (default: run winecfg as needed)')
    general.add_argument('--no-pty', dest='with_pty', default=True, action='store_false', help='refrain from creating a pseudo-terminal, stop protecting against TIOCSTI/TIOCLINUX hijacking (CAREFUL!) (default: create a pseudo-terminal)')
    general.add_argument('--no-wine', dest='with_wine', default=True, action='store_false', help='run PROGRAM without use of Wine (default: run command "wine PROGRAM [ARG ..]")')
    general.add_argument('--retry', dest='second_try', action='store_true', help='on non-zero exit code run PROGRAM a second time; helps to workaround weird graphics-related crashes (default: run command once)')


# Class to build command-line argument vectors
class ArgvBuilder:

    def __init__(self):
        self._groups = []

    def add(self, *args):
        if not args:
            return
        self._groups.append(args)

    def iter_flat(self):
        for group in self._groups:
            yield from group

    def iter_groups(self):
        yield from self._groups

    def announce_to(self, target):
        for i, group in enumerate(self._groups):
            prefix = '# ' if (i == 0) else ' ' * 4
            flat_args = shlex.join(group)
            suffix = '' if (i == len(self._groups) - 1) else ' \\'
            print(f'{prefix}{flat_args}{suffix}', file=target)


# Function to ensure a single trailing separator in a path
def single_trailing_sep(path):
    return path.rstrip(os.sep) + os.sep


# Function to parse a path and access mode from a string
def parse_path_colon_access(candidate):
    error_message = f'Value {candidate!r} does not match pattern "PATH:{{ro,rw}}".'
    if ':' not in candidate:
        raise ValueError(error_message)

    path, access_mode_candidate = candidate.rsplit(':', 1)
    if access_mode_candidate == 'ro':
        return path, AccessMode.READ_ONLY
    elif access_mode_candidate == 'rw':
        return path, AccessMode.READ_WRITE

    raise ValueError(error_message)


# Dataclass to represent a mount task
@dataclass
class MountTask:
    mode: MountMode
    target: str
    source: Optional[str] = None
    required: bool = True


# Function to generate a random hostname
def random_hostname():
    return ''.join(hex(random.randint(0, 15))[2:] for _ in range(12))


# Function to create the bubblewrap command-line arguments
def create_bwrap_argv(config):
    my_home = os.path.expanduser('~')
    mount_tasks = [
        MountTask(MountMode.TMPFS, '/'),
        MountTask(MountMode.BIND_RO, '/bin'),
        MountTask(MountMode.DEVTMPFS, '/dev'),
        MountTask(MountMode.BIND_DEV, '/dev/dri'),
        MountTask(MountMode.BIND_RO, '/etc'),
        MountTask(MountMode.BIND_RO, '/lib'),
        MountTask(MountMode.BIND_RO, '/lib32', required=False),
        MountTask(MountMode.BIND_RO, '/lib64'),
        MountTask(MountMode.PROC, '/proc'),
        MountTask(MountMode.BIND_RO, '/sys'),
        MountTask(MountMode.TMPFS, '/tmp'),
        MountTask(MountMode.BIND_RO, '/usr'),
        MountTask(MountMode.TMPFS, my_home),
    ]
    env_tasks = {var: None for var in ['HOME', 'TERM', 'USER', 'WINEDEBUG']}
    env_tasks['container'] = 'sandwine'
    unshare_args = ['--unshare-user', '--unshare-all']

    argv = ArgvBuilder()

    argv.add('bwrap')
    argv.add('--disable-userns')
    argv.add('--die-with-parent')

    # Hostname
    hostname = random_hostname()
    env_tasks['HOSTNAME'] = hostname
    argv.add('--hostname', hostname)

    # Networking
    if config.network:
        unshare_args += ['--share-net']
        mount_tasks += [
            MountTask(MountMode.BIND_RO, '/run/NetworkManager/resolv.conf', required=False),
            MountTask(MountMode.BIND_RO, '/run/systemd/resolve/stub-resolv.conf', required=False),
        ]

    # Sound
    if config.pulseaudio:
        pulseaudio_socket = f'/run/user/{os.getuid()}/pulse/native'
        env_tasks['PULSE_SERVER'] = f'unix:{pulseaudio_socket}'
        mount_tasks += [MountTask(MountMode.BIND_RW, pulseaudio_socket)]

    # X11
    if X11Mode(config.x11) != X11Mode.NONE:
        x11_unix_socket = X11Display(config.x11_display_number).get_unix_socket()
        mount_tasks += [MountTask(MountMode.BIND_RW, x11_unix_socket)]
        env_tasks['DISPLAY'] = f':{config.x11_display_number}'

    # Wine
    run_winecfg = (X11Mode(config.x11) != X11Mode.NONE and (config.configure or config.dotwine is None))
    dotwine_target_path = os.path.expanduser('~/.wine')
    if config.dotwine is not None:
        dotwine_source_path, dotwine_access = parse_path_colon_access(config.dotwine)
        mount_mode = MountMode.BIND_RW if dotwine_access == AccessMode.READ_WRITE else MountMode.BIND_RO
        mount_tasks += [MountTask(mount_mode, dotwine_target_path, source=dotwine_source_path)]

        if not os.path.exists(dotwine_source_path):
            _logger.info(f'Creating directory {dotwine_source_path!r}...')
            os.makedirs(dotwine_source_path, mode=0o700, exist_ok=True)
            run_winecfg = True
    else:
        mount_tasks += [MountTask(MountMode.TMPFS, dotwine_target_path)]

    # Extra binds
    for bind in config.extra_binds:
        mount_target, mount_access = parse_path_colon_access(bind)
        mount_mode = MountMode.BIND_RW if mount_access == AccessMode.READ_WRITE else MountMode.BIND_RO
        mount_tasks += [MountTask(mount_mode, os.path.abspath(mount_target))]

    # Program
    if os.sep in (config.argv_0 or ''):
        real_argv_0 = os.path.abspath(config.argv_0)
        mount_tasks += [
            MountTask(MountMode.BIND_RO, real_argv_0, required=False),
            MountTask(MountMode.BIND_RO, real_argv_0 + '.exe', required=False),
            MountTask(MountMode.BIND_RO, real_argv_0 + '.EXE', required=False),
        ]

    # Linux Namespaces
    argv.add(*unshare_args)

    # Mount stack
    sorted_mount_tasks = sorted(mount_tasks, key=attrgetter('target'))

    for mount_task in sorted_mount_tasks:
        if mount_task.mode == MountMode.TMPFS:
            argv.add('--tmpfs', mount_task.target)
        elif mount_task.mode == MountMode.DEVTMPFS:
            argv.add('--dev', mount_task.target)
        elif mount_task.mode == MountMode.PROC:
            argv.add('--proc', mount_task.target)
        elif mount_task.mode in (MountMode.BIND_RO, MountMode.BIND_RW, MountMode.BIND_DEV):
            if mount_task.source is None:
                mount_task.source = mount_task.target

            if not os.path.exists(mount_task.source) and not (X11Mode(config.x11) != X11Mode.NONE and mount_task.target == x11_unix_socket):
                if mount_task.required:
                    _logger.error(f'Path {mount_task.source!r} does not exist on the host, aborting.')
                    sys.exit(1)
                else:
                    _logger.debug(f'Path {mount_task.source!r} does not exist on the host, dropped from mount tasks.')
                    continue

            if mount_task.mode == MountMode.BIND_RO:
                argv.add('--ro-bind', mount_task.source, mount_task.target)
            elif mount_task.mode == MountMode.BIND_RW:
                argv.add('--bind', mount_task.source, mount_task.target)
            elif mount_task.mode == MountMode.BIND_DEV:
                argv.add('--dev-bind', mount_task.source, mount_task.target)
        else:
            assert False, f'Mode {mount_task.mode} unknown'

    # Filter ${PATH}
    candidate_paths = os.environ['PATH'].split(os.pathsep) + ['/usr/lib/wine']
    available_paths = [candidate_path for candidate_path in map(os.path.realpath, candidate_paths) if any(single_trailing_sep(candidate_path).startswith(single_trailing_sep(mount_task.target)) and mount_task.mode in (MountMode.BIND_RO, MountMode.BIND_RW, MountMode.BIND_DEV) for mount_task in reversed(sorted_mount_tasks))]
    env_tasks['PATH'] = os.pathsep.join(available_paths)

    # Create environment (meaning environment variables)
    argv.add('--clearenv')
    for env_var, env_value in sorted(env_tasks.items(), key=itemgetter(0)):
        if env_value is None:
            env_value = os.environ.get(env_var)
            if env_value is None:
                continue
        argv.add('--setenv', env_var, env_value)

    argv.add('--')

    # Wrap with wineserver (for clean shutdown, it defaults to 3 seconds timeout)
    if config.with_wine:
        argv.add('sh', '-c', 'wineserver -p0 && "$0" "$@" ; ret=$? ; wineserver -k ; exit ${ret}')

    # Add winecfg
    if run_winecfg and config.with_wine:
        argv.add('sh', '-c', 'winecfg && exec "$0" "$@"')

    # Add second try
    if config.second_try:
        argv.add('sh', '-c', '"$0" "$@" || exec "$0" "$@"')

    # Add Wine and PTY
    if config.argv_0 is not None:
        inner_argv = ['wine', config.argv_0] if config.with_wine else [config.argv_0]
        inner_argv.extend(config.argv_1_plus)

        if config.with_pty:
            argv.add('script', '-e', '-q', '-c', f'exec {shlex.join(inner_argv)}', '/dev/null')
        else:
            argv.add(*inner_argv)
    else:
        argv.add('true')

    return argv


# Function to ensure that the bubblewrap version is recent enough
def require_recent_bubblewrap():
    argv = ['bwrap', '--disable-userns', '--help']
    if subprocess.call(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        _logger.error('sandwine requires bubblewrap >=0.8.0, aborting.')
        sys.exit(1)


# Main function to orchestrate the execution of the sandboxed application
def main():
    exit_code = 0
    try:
        config = parse_command_line(sys.argv[1:])

        coloredlogs.install(level=logging.DEBUG)

        require_recent_bubblewrap()

        if X11Mode(config.x11) != X11Mode.NONE:
            if X11Mode(config.x11) == X11Mode.AUTO:
                config.x11 = detect_and_require_nested_x11()

            if X11Mode(config.x11) == X11Mode.HOST:
                config.x11_display_number = X11Display.find_used()
            else:
                minimum = 0
                if X11Mode(config.x11) == X11Mode.XPRA:
                    minimum = 10  # Avoids warning from Xpra for displays <=9
                config.x11_display_number = X11Display.find_unused(minimum)

            _logger.info('Using display ":%s"...', config.x11_display_number)

            x11context = create_x11_context(config.x11, config.x11_display_number, 1024, 768)
        else:
            x11context = nullcontext()

        argv_builder = create_bwrap_argv(config)
        argv_builder.announce_to(sys.stderr)

        argv = list(argv_builder.iter_flat())

        with x11context:
            try:
                exit_code = subprocess.call(argv)
            except FileNotFoundError:
                _logger.error(f'Command {argv[0]!r} is not available, aborting.')
                exit_code = 127

    except KeyboardInterrupt:
        exit_code = 128 + signal.SIGINT

    sys.exit(exit_code)
