# PAM module -----------------------------------------------------------------
pam_dep = cc.find_library('pam', required: true)
thread_dep = dependency('threads')
dl_dep = cc.find_library('dl', required: false)

pam_conf = configuration_data()
pam_conf.set_quoted('FA_SOCKET_PATH', get_option('socket_path'))
pam_conf.set_quoted('FA_MARKER_DIR', get_option('marker_dir'))
pam_conf.set_quoted('FA_SERVICE_USER', get_option('service_user'))
pam_conf.set_quoted('GETTEXT_PACKAGE', meson.project_name())
pam_conf.set_quoted('LOCALEDIR', get_option('prefix') / get_option('localedir'))
pam_config_h = configure_file(output: 'config.h', configuration: pam_conf)

pam_module = shared_module(
  'pam_facial_auth',
  'pam_facial_auth.c',
  name_prefix: '',
  dependencies: [pam_dep, thread_dep, dl_dep],
  # The module must never be unloaded while an abandoned prompt thread may
  # still be executing code from it.
  link_args: ['-Wl,-z,nodelete', '-Wl,-z,relro', '-Wl,-z,now'],
  c_args: ['-D_FORTIFY_SOURCE=2'],
  include_directories: include_directories('.'),
  install: true,
  install_dir: pam_moduledir_default,
)
