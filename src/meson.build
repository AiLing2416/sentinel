pkgdatadir = get_option('datadir') / meson.project_name()
pythondir = get_option('python_dir')

if pythondir == ''
  pythondir = get_option('libdir') / 'python' + import('python').find_installation('python3').language_version() / 'site-packages'
endif

conf_data = configuration_data()
conf_data.set('VERSION', meson.project_version())
conf_data.set('pkgdatadir', pkgdatadir)
conf_data.set('application_id', APPLICATION_ID)

# We install the whole src directory as a package
install_subdir('.',
  install_dir: pythondir / 'sentinel',
  exclude_files: ['meson.build'],
)

# Entry point script
configure_file(
  input: 'main.py',
  output: 'sentinel',
  configuration: conf_data,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x'
)
