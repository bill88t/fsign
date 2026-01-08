# Bill Sideris <bill88t@feline.gr>

pkgname=fsign
pkgver=1.0.0
pkgrel=1
pkgdesc='A trivial folder signing utility'
arch=('any')
url='https://github.com/bill88t/fsign'
license=('GPLv3')
source=('fsign.py')
sha256sums=('7fd575f30e537bb330ad13941a2523a947bb61d859c99bead26bb8b4d7530b46')

package() {
    install -Dm755 "${srcdir}/fsign.py" "${pkgdir}/usr/bin/fsign"
}
