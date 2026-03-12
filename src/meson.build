pkgdatadir = get_option('datadir') / meson.project_name()
mod_py = import('python')
python = mod_py.find_installation('python3')
pythondir = python.get_install_dir()

conf_data = configuration_data()
conf_data.set('VERSION', meson.project_version())
conf_data.set('pkgdatadir', pkgdatadir)
conf_data.set('application_id', APPLICATION_ID)
conf_data.set('PYTHONDIR', pythondir / 'sentinel')

# We install the whole src directory as a package
install_subdir('.',
  install_dir: pythondir / 'sentinel',
  exclude_files: ['meson.build', 'main.py.in'],
)

# Entry point script
configure_file(
  input: 'main.py.in',
  output: 'sentinel',
  configuration: conf_data,
  install_dir: get_option('bindir'),
  install_mode: 'rwxr-xr-x'
)
