project('sentinel',
  version: '0.2.0',
  meson_version: '>= 0.62.0',
  default_options: [ 'warning_level=2' ],
)

i18n = import('i18n')
gnome = import('gnome')

# Standard variables
APPLICATION_ID = 'io.github.ailing2416.sentinel'

subdir('data')
subdir('src')
subdir('po')

gnome.post_install(
  glib_compile_schemas: true,
  gtk_update_icon_cache: true,
  update_desktop_database: true,
)
