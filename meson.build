project('facial-auth', 'c',
  version: '0.1.0',
  license: 'MIT',
  meson_version: '>= 1.0.0',
  default_options: ['c_std=gnu11', 'warning_level=2', 'buildtype=debugoptimized'])

cc = meson.get_compiler('c')

# Resolve the default PAM module directory lazily (needs libdir).
if get_option('pam_moduledir') == ''
  pam_moduledir_default = get_option('prefix') / get_option('libdir') / 'security'
else
  pam_moduledir_default = get_option('pam_moduledir')
endif

subdir('pam')

if get_option('tests')
  subdir('tests/pam')
endif
