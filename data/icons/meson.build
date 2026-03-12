# Install scalable SVG icon
install_data('hicolor/scalable/apps/io.github.ailing2416.sentinel.svg',
  install_dir: get_option('datadir') / 'icons' / 'hicolor' / 'scalable' / 'apps'
)

# Install symbolic icon
install_data('hicolor/symbolic/apps/io.github.ailing2416.sentinel-symbolic.svg',
  install_dir: get_option('datadir') / 'icons' / 'hicolor' / 'symbolic' / 'apps'
)

# OS icons (used by the application internally)
os_icons = [
  'almalinux.svg', 'almalinux-symbolic.svg', 'alma.svg', 'alma-symbolic.svg',
  'alpine.svg', 'alpine-symbolic.svg', 'amazon.svg', 'amazon-symbolic.svg',
  'amzn.svg', 'amzn-symbolic.svg', 'arch.svg', 'arch-symbolic.svg',
  'centos.svg', 'centos-symbolic.svg', 'darwin.svg', 'darwin-symbolic.svg',
  'debian.svg', 'debian-symbolic.svg', 'fedora.svg', 'fedora-symbolic.svg',
  'freebsd.svg', 'freebsd-symbolic.svg', 'linux.svg', 'linux-symbolic.svg',
  'mac.svg', 'mac-symbolic.svg', 'opensuse-leap.svg', 'opensuse-leap-symbolic.svg',
  'opensuse.svg', 'opensuse-symbolic.svg', 'opensuse-tumbleweed.svg', 'opensuse-tumbleweed-symbolic.svg',
  'redhat.svg', 'redhat-symbolic.svg', 'rhel.svg', 'rhel-symbolic.svg',
  'rockylinux.svg', 'rockylinux-symbolic.svg', 'rocky.svg', 'rocky-symbolic.svg',
  'ubuntu.svg', 'ubuntu-symbolic.svg', 'windows.svg', 'windows-symbolic.svg'
]

foreach icon : os_icons
  install_data('os' / icon,
    install_dir: get_option('datadir') / 'sentinel' / 'icons' / 'os'
  )
endforeach
