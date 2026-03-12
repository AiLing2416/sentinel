desktop_file = i18n.merge_file(
  input: 'io.github.ailing2416.sentinel.desktop.in',
  output: 'io.github.ailing2416.sentinel.desktop',
  type: 'desktop',
  po_dir: '../po',
  install: true,
  install_dir: get_option('datadir') / 'applications'
)

desktop_utils = find_program('desktop-file-validate', required: false)
if desktop_utils.found()
  test('Validate desktop file', desktop_utils, args: [desktop_file])
endif

appdata_file = i18n.merge_file(
  input: 'io.github.ailing2416.sentinel.metainfo.xml.in',
  output: 'io.github.ailing2416.sentinel.metainfo.xml',
  po_dir: '../po',
  install: true,
  install_dir: get_option('datadir') / 'metainfo'
)

appstream_util = find_program('appstream-util', required: false)
if appstream_util.found()
  test('Validate appdata file', appstream_util, args: ['validate', appdata_file])
endif

install_data('io.github.ailing2416.sentinel.gschema.xml',
  install_dir: get_option('datadir') / 'glib-2.0' / 'schemas'
)

compile_schemas = find_program('glib-compile-schemas', required: false)
if compile_schemas.found()
  test('Validate schema file', compile_schemas, args: ['--strict', '--dry-run', meson.current_source_dir()])
endif

subdir('icons')
