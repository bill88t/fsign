# Bill Sideris <bill88t@feline.gr>

pkgname=fsign
pkgver=1.1.0
pkgrel=1
pkgdesc='A trivial folder signing utility'
arch=('any')
url='https://github.com/bill88t/fsign'
license=('GPLv3')
makedepends=('python-pytest' 'python-pytest-cov')
source=('fsign.py' 'test_fsign.py' 'requirements-dev.txt')
sha256sums=('80234347942be89ef8103698cc7fe3675b1d3a2957922e65ab261aa701fbae7d'
            '8a721cf461fa10367e6e549bdb470ebf067ab149766fe8e72d9674f87b33cf91'
            'e3824de8550a59f452dc5541940dd1adcb8e332bef9d53951f3894217c440efc')

check() {
    cd "${srcdir}"
    python -m pytest test_fsign.py -v
}

package() {
    install -Dm755 "${srcdir}/fsign.py" "${pkgdir}/usr/bin/fsign"
}
