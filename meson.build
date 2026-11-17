project('facial-auth', 'c',
  version: '0.1.0',
  license: 'MIT',
  meson_version: '>= 1.0.0',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=debugoptimized'])

cc = meson.get_compiler('c')
prefix = get_option('prefix')
datadir = prefix / get_option('datadir')

# PAM module -------------------------------------------------------------
if get_option('pam_moduledir') == ''
  pam_moduledir_default = prefix / get_option('libdir') / 'security'
else
  pam_moduledir_default = get_option('pam_moduledir')
endif
subdir('pam')

# Python package (daemon, CLI, settings app) -------------------------------
py = import('python').find_installation(get_option('python'), pure: true)
if get_option('pythondir') == ''
  pythondir = py.get_install_dir()
else
  pythondir = get_option('pythondir')
endif
install_subdir('src/facial_auth', install_dir: pythondir,
  exclude_directories: ['__pycache__'], exclude_files: ['.gitkeep'])

install_data('bin/facial-auth', 'bin/facial-auth-settings',
  install_dir: prefix / get_option('bindir'), install_mode: 'rwxr-xr-x')
# systemd/D-Bus units refer to this exact path
install_data('bin/facial-authd',
  install_dir: prefix / 'libexec' / 'facial-auth', install_mode: 'rwxr-xr-x')

# System integration -----------------------------------------------------
install_data('data/systemd/facial-authd.service', 'data/systemd/facial-authd.socket',
  install_dir: prefix / 'lib' / 'systemd' / 'system')
install_data('data/sysusers/facial-auth.conf', install_dir: prefix / 'lib' / 'sysusers.d')
install_data('data/dbus/io.github.neomars.FacialAuth1.conf',
  install_dir: datadir / 'dbus-1' / 'system.d')
install_data('data/dbus/io.github.neomars.FacialAuth1.service',
  install_dir: datadir / 'dbus-1' / 'system-services')
install_data('data/polkit/io.github.neomars.FacialAuth1.policy',
  install_dir: datadir / 'polkit-1' / 'actions')
install_data('data/pam-configs/facial-auth', install_dir: datadir / 'pam-configs')
install_data('data/desktop/io.github.neomars.FacialAuth.desktop',
  install_dir: datadir / 'applications')
install_data('data/icons/io.github.neomars.FacialAuth.svg',
  install_dir: datadir / 'icons' / 'hicolor' / 'scalable' / 'apps')
install_data('data/config/defaults.conf', install_dir: datadir / 'facial-auth')
install_data('data/config/facial-auth.conf',
  install_dir: get_option('sysconfdir') / 'facial-auth')

install_man('man/facial-auth.1', 'man/facial-auth-settings.1')
install_man('man/pam_facial_auth.8')

subdir('po')

if get_option('tests')
  subdir('tests/pam')
endif
