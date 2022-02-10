from typing import Dict, Tuple
from ipaddress import IPv4Network, IPv4Address

from .errors import GeneralError


# Regional Internet Registry IPv4 Allocations:
# https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtml
# and https://data.iana.org/rdap/ipv4.json
class IPv4Allocations:
    _allocations: Dict[IPv4Network, Dict[str, str]] = {
        IPv4Network('1.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('2.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('3.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('4.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('5.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('6.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('7.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('8.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('9.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('11.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('12.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('13.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('14.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('15.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('16.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('17.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('18.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('19.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('20.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('21.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('22.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('23.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('24.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('25.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('26.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('27.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('28.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('29.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('30.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('31.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('32.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('33.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('34.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('35.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('36.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('37.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('38.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('39.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('40.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('41.0.0.0/8'): {'rdap':'https://rdap.afrinic.net/rdap/','whois':'whois.afrinic.net'},
        IPv4Network('42.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('43.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('44.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('45.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('46.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('47.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('48.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('49.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('50.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('51.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('52.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('53.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('54.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('55.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('56.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('57.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('58.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('59.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('60.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('61.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('62.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('63.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('64.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('65.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('66.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('67.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('68.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('69.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('70.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('71.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('72.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('73.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('74.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('75.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('76.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('77.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('78.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('79.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('80.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('81.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('82.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('83.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('84.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('85.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('86.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('87.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('88.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('89.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('90.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('91.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('92.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('93.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('94.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('95.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('96.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('97.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('98.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('99.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('100.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('101.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('102.0.0.0/8'): {'rdap':'https://rdap.afrinic.net/rdap/','whois':'whois.afrinic.net'},
        IPv4Network('103.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('104.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('105.0.0.0/8'): {'rdap':'https://rdap.afrinic.net/rdap/','whois':'whois.afrinic.net'},
        IPv4Network('106.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('107.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('108.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('109.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('110.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('111.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('112.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('113.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('114.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('115.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('116.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('117.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('118.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('119.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('120.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('121.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('122.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('123.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('124.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('125.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('126.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('128.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('129.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('130.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('131.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('132.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('133.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('134.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('135.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('136.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('137.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('138.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('139.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('140.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('141.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('142.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('143.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('144.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('145.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('146.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('147.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('148.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('149.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('150.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('151.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('152.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('153.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('154.0.0.0/8'): {'rdap':'https://rdap.afrinic.net/rdap/','whois':'whois.afrinic.net'},
        IPv4Network('155.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('156.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('157.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('158.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('159.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('160.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('161.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('162.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('163.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('164.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('165.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('166.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('167.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('168.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('169.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('170.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('171.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('172.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('173.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('174.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('175.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('176.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('177.0.0.0/8'): {'rdap':'https://rdap.lacnic.net/rdap/','whois':'whois.lacnic.net'},
        IPv4Network('178.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('179.0.0.0/8'): {'rdap':'https://rdap.lacnic.net/rdap/','whois':'whois.lacnic.net'},
        IPv4Network('180.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('181.0.0.0/8'): {'rdap':'https://rdap.lacnic.net/rdap/','whois':'whois.lacnic.net'},
        IPv4Network('182.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('183.0.0.0/8'): {'rdap':'https://rdap.apnic.net/','whois':'whois.apnic.net'},
        IPv4Network('184.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('185.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('186.0.0.0/8'): {'rdap':'https://rdap.lacnic.net/rdap/','whois':'whois.lacnic.net'},
        IPv4Network('187.0.0.0/8'): {'rdap':'https://rdap.lacnic.net/rdap/','whois':'whois.lacnic.net'},
        IPv4Network('188.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('189.0.0.0/8'): {'rdap':'https://rdap.lacnic.net/rdap/','whois':'whois.lacnic.net'},
        IPv4Network('190.0.0.0/8'): {'rdap':'https://rdap.lacnic.net/rdap/','whois':'whois.lacnic.net'},
        IPv4Network('191.0.0.0/8'): {'rdap':'https://rdap.lacnic.net/rdap/','whois':'whois.lacnic.net'},
        IPv4Network('192.0.0.0/8'): {'rdap':'https://rdap.arin.net/registry','whois':'whois.arin.net'},
        IPv4Network('193.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('194.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
        IPv4Network('195.0.0.0/8'): {'rdap':'https://rdap.db.ripe.net/','whois':'whois.ripe.net'},
    }
    
    def get_servers(self, ipv4: IPv4Address) -> Tuple[str, str]:
        """
        Retrieves the WHOIS and RDAP servers for the given IPv4 address.
        """
        for network, servers in self._allocations.items():
            if ipv4 in network:
                return servers['rdap'], servers['whois']
        # no match
        raise GeneralError(f'No WHOIS or RDAP server for: {ipv4}')


# Top Level Domain WHOIS Server Names
# Retrieved from https://www.iana.org/domains/root/db

class CountryCodeTLD:
    AC = 'whois.nic.ac'
    AD = None
    AE = 'whois.aeda.net.ae'
    AF = 'whois.nic.af'
    AG = 'whois.nic.ag'
    AI = 'whois.nic.ai'
    AL = None
    AM = 'whois.amnic.net'
    AN = None
    AO = None
    AQ = None
    AR = 'whois.nic.ar'
    AS = 'whois.nic.as'
    AT = 'whois.nic.at'
    AU = 'whois.auda.org.au'
    AW = 'whois.nic.aw'
    AX = 'whois.ax'
    AZ = None
    BA = None
    BB = None
    BD = None
    BE = 'whois.dns.be'
    BF = None
    BG = 'whois.register.bg'
    BH = None
    BI = 'whois1.nic.bi'
    BJ = 'whois.nic.bj'
    BL = None
    BM = None
    BN = 'whois.bnnic.bn'
    BO = 'whois.nic.bo'
    BQ = None
    BR = 'whois.registro.br'
    BS = None
    BT = None
    BV = None
    BW = 'whois.nic.net.bw'
    BY = 'whois.cctld.by'
    BZ = None
    CA = 'whois.cira.ca'
    CC = 'ccwhois.verisign-grs.com'
    CD = None
    CF = 'whois.dot.cf'
    CG = None
    CH = 'whois.nic.ch'
    CI = 'whois.nic.ci'
    CK = None
    CL = 'whois.nic.cl'
    CM = None
    CN = 'whois.cnnic.cn'
    CO = 'whois.nic.co'
    CR = 'whois.nic.cr'
    CU = None
    CV = None
    CW = None
    CX = 'whois.nic.cx'
    CY = None
    CZ = 'whois.nic.cz'
    DE = 'whois.denic.de'
    DJ = None
    DK = 'whois.dk-hostmaster.dk'
    DM = 'whois.nic.dm'
    DO = 'whois.nic.do'
    DZ = 'whois.nic.dz'
    EC = 'whois.nic.ec'
    EE = 'whois.tld.ee'
    EG = None
    EH = None
    ER = None
    ES = 'whois.nic.es'
    ET = None
    EU = 'whois.eu'
    FI = 'whois.fi'
    FJ = None
    FK = None
    FM = 'whois.nic.fm'
    FO = 'whois.nic.fo'
    FR = 'whois.nic.fr'
    GA = None
    GB = None
    GD = 'whois.nic.gd'
    GE = 'whois.nic.ge'
    GF = 'whois.mediaserv.net'
    GG = 'whois.gg'
    GH = None
    GI = 'whois2.afilias-grs.net'
    GL = 'whois.nic.gl'
    GM = None
    GN = None
    GP = 'whois.nic.gp'
    GQ = 'whois.dominio.gq'
    GR = None
    GS = 'whois.nic.gs'
    GT = None
    GU = None
    GW = None
    GY = 'whois.registry.gy'
    HK = 'whois.hkirc.hk'
    HM = 'whois.registry.hm'
    HN = 'whois.nic.hn'
    HR = 'whois.dns.hr'
    HT = 'whois.nic.ht'
    HU = 'whois.nic.hu'
    ID = 'whois.id'
    IE = 'whois.weare.ie'
    IL = 'whois.isoc.org.il'
    IM = 'whois.nic.im'
    IN = 'whois.registry.in'
    IO = 'whois.nic.io'
    IQ = 'whois.cmc.iq'
    IR = 'whois.nic.ir'
    IS = 'whois.isnic.is'
    IT = 'whois.nic.it'
    JE = 'whois.je'
    JM = None
    JO = None
    JP = 'whois.jprs.jp'
    KE = 'whois.kenic.or.ke'
    KG = 'whois.kg'
    KH = None
    KI = 'whois.nic.ki'
    KM = None
    KN = 'whois.nic.kn'
    KP = None
    KR = 'whois.kr'
    KW = None
    KY = 'whois.kyregistry.ky'
    KZ = 'whois.nic.kz'
    LA = 'whois.nic.la'
    LB = None
    LC = None
    LI = 'whois.nic.li'
    LK = None
    LR = None
    LS = 'whois.nic.ls'
    LT = 'whois.domreg.lt'
    LU = 'whois.dns.lu'
    LV = 'whois.nic.lv'
    LY = 'whois.nic.ly'
    MA = 'whois.registre.ma'
    MC = None
    MD = 'whois.nic.md'
    ME = 'whois.nic.me'
    MF = None
    MG = 'whois.nic.mg'
    MH = None
    MK = 'whois.marnet.mk'
    ML = 'whois.dot.ml'
    MM = 'whois.registry.gov.mm'
    MN = 'whois.nic.mn'
    MO = 'whois.monic.mo'
    MP = 'whois.nic.mp'
    MQ = 'whois.mediaserv.net'
    MR = 'whois.nic.mr'
    MS = 'whois.nic.ms'
    MT = None
    MU = 'whois.nic.mu'
    MV = None
    MW = 'whois.nic.mw'
    MX = 'whois.mx'
    MY = 'whois.mynic.my'
    MZ = 'whois.nic.mz'
    NA = 'whois.na-nic.com.na'
    NC = 'whois.nc'
    NE = None
    NF = 'whois.nic.nf'
    NG = 'whois.nic.net.ng'
    NI = None
    NL = 'whois.domain-registry.nl'
    NO = 'whois.norid.no'
    NP = None
    NR = None
    NU = 'whois.iis.nu'
    NZ = 'whois.srs.net.nz'
    OM = 'whois.registry.om'
    PA = None
    PE = 'kero.yachay.pe'
    PF = 'whois.registry.pf'
    PG = None
    PH = None
    PK = None
    PL = 'whois.dns.pl'
    PM = 'whois.nic.pm'
    PN = None
    PR = 'whois.afilias-srs.net'
    PS = None
    PT = 'whois.dns.pt'
    PW = 'whois.nic.pw'
    PY = None
    QA = 'whois.registry.qa'
    RE = 'whois.nic.re'
    RO = 'whois.rotld.ro'
    RS = 'whois.rnids.rs'
    RU = 'whois.tcinet.ru'
    RW = None
    SA = 'whois.nic.net.sa'
    SB = 'whois.nic.net.sb'
    SC = 'whois2.afilias-grs.net'
    SD = None
    SE = 'whois.iis.se'
    SG = 'whois.sgnic.sg'
    SH = 'whois.nic.sh'
    SI = 'whois.register.si'
    SJ = None
    SK = 'whois.sk-nic.sk'
    SL = None
    SM = 'whois.nic.sm'
    SN = 'whois.nic.sn'
    SO = 'whois.nic.so'
    SR = None
    SS = 'whois.nic.ss'
    ST = 'whois.nic.st'
    SU = 'whois.tcinet.ru'
    SV = None
    SX = 'whois.sx'
    SY = 'whois.tld.sy'
    SZ = None
    TC = 'whois.nic.tc'
    TD = 'whois.nic.td'
    TF = 'whois.nic.tf'
    TG = 'whois.nic.tg'
    TH = 'whois.thnic.co.th'
    TJ = None
    TK = 'whois.dot.tk'
    TL = 'whois.nic.tl'
    TM = 'whois.nic.tm'
    TN = 'whois.ati.tn'
    TO = 'whois.tonic.to'
    TP = None
    TR = 'whois.nic.tr'
    TT = None
    TV = 'tvwhois.verisign-grs.com'
    TW = 'whois.twnic.net.tw'
    TZ = 'whois.tznic.or.tz'
    UA = 'whois.ua'
    UG = 'whois.co.ug'
    UK = 'whois.nic.uk'
    UM = None
    US = 'whois.nic.us'
    UY = 'whois.nic.org.uy'
    UZ = 'whois.cctld.uz'
    VA = None
    VC = 'whois2.afilias-grs.net'
    VE = 'whois.nic.ve'
    VG = 'whois.nic.vg'
    VI = None
    VN = None
    VU = 'whois.dnrs.neustar'
    WF = 'whois.nic.wf'
    WS = 'whois.website.ws'
    XN__2SCRJ9C = 'whois.registry.in'
    XN__3E0B707E = 'whois.kr'
    XN__3HCRJ9C = 'whois.registry.in'
    XN__45BR5CYL = 'whois.registry.in'
    XN__45BRJ9C = 'whois.registry.in'
    XN__54B7FTA0CC = None
    XN__80AO21A = 'whois.nic.kz'
    XN__90A3AC = 'whois.rnids.rs'
    XN__90AE = 'whois.imena.bg'
    XN__90AIS = 'whois.cctld.by'
    XN__CLCHC0EA0B2G2A9GCD = 'whois.sgnic.sg'
    XN__D1ALF = 'whois.marnet.mk'
    XN__E1A4C = 'whois.eu'
    XN__FIQS8S = 'cwhois.cnnic.cn'
    XN__FIQZ9S = 'cwhois.cnnic.cn'
    XN__FPCRJ9C3D = 'whois.registry.in'
    XN__FZC2C9E2C = None
    XN__GECRJ9C = 'whois.registry.in'
    XN__H2BREG3EVE = 'whois.registry.in'
    XN__H2BRJ9C = 'whois.registry.in'
    XN__H2BRJ9C8C = 'whois.registry.in'
    XN__J1AMH = 'whois.dotukr.com'
    XN__J6W193G = 'whois.hkirc.hk'
    XN__KPRW13D = 'whois.twnic.net.tw'
    XN__KPRY57D = 'whois.twnic.net.tw'
    XN__L1ACC = None
    XN__LGBBAT1AD8J = 'whois.nic.dz'
    XN__MGB9AWBF = 'whois.registry.om'
    XN__MGBA3A4F16A = 'whois.nic.ir'
    XN__MGBAAM7A8H = 'whois.aeda.net.ae'
    XN__MGBAI9AZGQP6J = None
    XN__MGBAYH7GPA = None
    XN__MGBBH1A = 'whois.registry.in'
    XN__MGBBH1A71E = 'whois.registry.in'
    XN__MGBC0A9AZCG = None
    XN__MGBERP4A5D4AR = 'whois.nic.net.sa'
    XN__MGBGU82A = 'whois.registry.in'
    XN__MGBPL2FH = None
    XN__MGBTX2B = 'whois.cmc.iq'
    XN__MGBX4CD0AB = 'whois.mynic.my'
    XN__MIX891F = 'whois.monic.mo'
    XN__NODE = 'whois.itdc.ge'
    XN__O3CW4H = 'whois.thnic.co.th'
    XN__OGBPF8FL = 'whois.tld.sy'
    XN__P1AI = 'whois.tcinet.ru'
    XN__PGBS0DH = 'whois.ati.tn'
    XN__QXAM = None
    XN__RVC1E0AM3E = 'whois.registry.in'
    XN__S9BRJ9C = 'whois.registry.in'
    XN__WGBH1C = None
    XN__WGBL6A = 'whois.registry.qa'
    XN__XKC2AL3HYE2A = None
    XN__XKC2DL3A5EE0H = 'whois.registry.in'
    XN__Y9A3AQ = 'whois.amnic.net'
    XN__YFRO4I67O = 'whois.sgnic.sg'
    XN__YGBI2AMMX = 'whois.pnina.ps'
    YE = None
    YT = 'whois.nic.yt'
    ZA = None
    ZM = 'whois.zicta.zm'
    ZW = None


class GenericTLD:
    AAA = None
    AARP = 'whois.nic.aarp'
    ABARTH = 'whois.afilias-srs.net'
    ABB = None
    ABBOTT = None
    ABBVIE = 'whois.afilias-srs.net'
    ABC = 'whois.nic.abc'
    ABLE = None
    ABOGADO = 'whois.nic.abogado'
    ABUDHABI = 'whois.nic.abudhabi'
    ACADEMY = 'whois.nic.academy'
    ACCENTURE = None
    ACCOUNTANT = 'whois.nic.accountant'
    ACCOUNTANTS = 'whois.nic.accountants'
    ACO = 'whois.nic.aco'
    ACTIVE = None
    ACTOR = 'whois.nic.actor'
    ADAC = 'whois.nic.adac'
    ADS = 'whois.nic.google'
    ADULT = 'whois.registrar.adult'
    AEG = 'whois.nic.aeg'
    AETNA = None
    AFAMILYCOMPANY = 'whois.nic.afamilycompany'
    AFL = 'whois.nic.afl'
    AFRICA = 'africa-whois.registry.net.za'
    AGAKHAN = 'whois.afilias-srs.net'
    AGENCY = 'whois.nic.agency'
    AIG = None
    AIGO = None
    AIRBUS = 'whois.nic.airbus'
    AIRFORCE = 'whois.nic.airforce'
    AIRTEL = 'whois.nic.airtel'
    AKDN = 'whois.afilias-srs.net'
    ALFAROMEO = 'whois.afilias-srs.net'
    ALIBABA = 'whois.nic.alibaba'
    ALIPAY = 'whois.nic.alipay'
    ALLFINANZ = 'whois.nic.allfinanz'
    ALLSTATE = 'whois.afilias-srs.net'
    ALLY = 'whois.nic.ally'
    ALSACE = 'whois-alsace.nic.fr'
    ALSTOM = 'whois.nic.alstom'
    AMERICANEXPRESS = None
    AMERICANFAMILY = 'whois.nic.americanfamily'
    AMEX = None
    AMFAM = 'whois.nic.amfam'
    AMICA = None
    AMSTERDAM = 'whois.nic.amsterdam'
    ANALYTICS = None
    ANDROID = 'whois.nic.google'
    ANQUAN = 'whois.teleinfo.cn'
    ANZ = 'whois.nic.anz'
    AOL = 'whois.nic.aol'
    APARTMENTS = 'whois.nic.apartments'
    APP = 'whois.nic.google'
    APPLE = 'whois.afilias-srs.net'
    AQUARELLE = 'whois.nic.aquarelle'
    ARAMCO = None
    ARCHI = 'whois.afilias.net'
    ARMY = 'whois.nic.army'
    ART = 'whois.nic.art'
    ARTE = 'whois.nic.arte'
    ASDA = 'whois.nic.asda'
    ASSOCIATES = 'whois.nic.associates'
    ATHLETA = None
    ATTORNEY = 'whois.nic.attorney'
    AUCTION = 'whois.nic.auction'
    AUDI = 'whois.afilias-srs.net'
    AUDIBLE = 'whois.nic.audible'
    AUDIO = 'whois.uniregistry.net'
    AUSPOST = 'whois.nic.auspost'
    AUTHOR = 'whois.nic.author'
    AUTO = 'whois.nic.auto'
    AUTOS = 'whois.afilias-srs.net'
    AVIANCA = 'whois.afilias-srs.net'
    AWS = 'whois.nic.aws'
    AXA = None
    AZURE = None
    BABY = 'whois.nic.baby'
    BAIDU = 'whois.gtld.knet.cn'
    BANAMEX = None
    BANANAREPUBLIC = None
    BAND = 'whois.nic.band'
    BANK = 'whois.nic.bank'
    BAR = 'whois.nic.bar'
    BARCELONA = 'whois.nic.barcelona'
    BARCLAYCARD = 'whois.nic.barclaycard'
    BARCLAYS = 'whois.nic.barclays'
    BAREFOOT = 'whois.nic.barefoot'
    BARGAINS = 'whois.nic.bargains'
    BASEBALL = None
    BASKETBALL = 'whois.nic.basketball'
    BAUHAUS = 'whois.nic.bauhaus'
    BAYERN = 'whois.nic.bayern'
    BBC = 'whois.nic.bbc'
    BBT = 'whois.nic.bbt'
    BBVA = 'whois.nic.bbva'
    BCG = 'whois.nic.bcg'
    BCN = 'whois.nic.bcn'
    BEATS = 'whois.afilias-srs.net'
    BEAUTY = 'whois.nic.beauty'
    BEER = 'whois.nic.beer'
    BENTLEY = 'whois.nic.bentley'
    BERLIN = 'whois.nic.berlin'
    BEST = 'whois.nic.best'
    BESTBUY = 'whois.nic.bestbuy'
    BET = 'whois.afilias.net'
    BHARTI = None
    BIBLE = 'whois.nic.bible'
    BID = 'whois.nic.bid'
    BIKE = 'whois.nic.bike'
    BING = None
    BINGO = 'whois.nic.bingo'
    BIO = 'whois.afilias.net'
    BLACK = 'whois.afilias.net'
    BLACKFRIDAY = 'whois.uniregistry.net'
    BLANCO = None
    BLOCKBUSTER = 'whois.nic.blockbuster'
    BLOG = 'whois.nic.blog'
    BLOOMBERG = None
    BLUE = 'whois.afilias.net'
    BMS = 'whois.nic.bms'
    BMW = 'whois.nic.bmw'
    BNL = None
    BNPPARIBAS = 'whois.afilias-srs.net'
    BOATS = 'whois.afilias-srs.net'
    BOEHRINGER = 'whois.afilias-srs.net'
    BOFA = 'whois.nic.bofa'
    BOM = 'whois.gtlds.nic.br'
    BOND = 'whois.nic.bond'
    BOO = 'whois.nic.google'
    BOOK = 'whois.nic.book'
    BOOKING = None
    BOOTS = None
    BOSCH = 'whois.nic.bosch'
    BOSTIK = 'whois.nic.bostik'
    BOSTON = 'whois.nic.boston'
    BOT = 'whois.nic.bot'
    BOUTIQUE = 'whois.nic.boutique'
    BOX = 'whois.nic.box'
    BRADESCO = 'whois.nic.bradesco'
    BRIDGESTONE = 'whois.nic.bridgestone'
    BROADWAY = 'whois.nic.broadway'
    BROKER = 'whois.nic.broker'
    BROTHER = 'whois.nic.brother'
    BRUSSELS = 'whois.nic.brussels'
    BUDAPEST = 'whois.nic.budapest'
    BUGATTI = 'whois.afilias-srs.net'
    BUILD = 'whois.nic.build'
    BUILDERS = 'whois.nic.builders'
    BUSINESS = 'whois.nic.business'
    BUY = 'whois.nic.buy'
    BUZZ = 'whois.nic.buzz'
    BZH = 'whois.nic.bzh'
    CAB = 'whois.nic.cab'
    CAFE = 'whois.nic.cafe'
    CAL = 'whois.nic.google'
    CALL = 'whois.nic.call'
    CALVINKLEIN = None
    CAM = 'whois.nic.cam'
    CAMERA = 'whois.nic.camera'
    CAMP = 'whois.nic.camp'
    CANCERRESEARCH = 'whois.nic.cancerresearch'
    CANON = 'whois.nic.canon'
    CAPETOWN = 'capetown-whois.registry.net.za'
    CAPITAL = 'whois.nic.capital'
    CAPITALONE = 'whois.nic.capitalone'
    CAR = 'whois.nic.car'
    CARAVAN = None
    CARDS = 'whois.nic.cards'
    CARE = 'whois.nic.care'
    CAREER = 'whois.nic.career'
    CAREERS = 'whois.nic.careers'
    CARS = 'whois.nic.cars'
    CARTIER = None
    CASA = 'whois.nic.casa'
    CASE = 'whois.nic.case'
    CASEIH = None
    CASH = 'whois.nic.cash'
    CASINO = 'whois.nic.casino'
    CATERING = 'whois.nic.catering'
    CATHOLIC = 'whois.nic.catholic'
    CBA = 'whois.nic.cba'
    CBN = None
    CBRE = None
    CBS = 'whois.afilias-srs.net'
    CEB = None
    CENTER = 'whois.nic.center'
    CEO = 'whois.nic.ceo'
    CERN = 'whois.afilias-srs.net'
    CFA = 'whois.nic.cfa'
    CFD = 'whois.nic.cfd'
    CHANEL = 'whois.nic.chanel'
    CHANNEL = 'whois.nic.google'
    CHASE = None
    CHAT = 'whois.nic.chat'
    CHEAP = 'whois.nic.cheap'
    CHINTAI = 'whois.nic.chintai'
    CHLOE = None
    CHRISTMAS = 'whois.uniregistry.net'
    CHROME = 'whois.nic.google'
    CHRYSLER = None
    CHURCH = 'whois.nic.church'
    CIPRIANI = 'whois.afilias-srs.net'
    CIRCLE = 'whois.nic.circle'
    CISCO = None
    CITADEL = None
    CITI = None
    CITIC = None
    CITY = 'whois.nic.city'
    CITYEATS = 'whois.nic.cityeats'
    CLAIMS = 'whois.nic.claims'
    CLEANING = 'whois.nic.cleaning'
    CLICK = 'whois.uniregistry.net'
    CLINIC = 'whois.nic.clinic'
    CLINIQUE = 'whois.nic.clinique'
    CLOTHING = 'whois.nic.clothing'
    CLOUD = 'whois.nic.cloud'
    CLUB = 'whois.nic.club'
    CLUBMED = 'whois.nic.clubmed'
    COACH = 'whois.nic.coach'
    CODES = 'whois.nic.codes'
    COFFEE = 'whois.nic.coffee'
    COLLEGE = 'whois.nic.college'
    COLOGNE = 'whois.ryce-rsp.com'
    COM = 'whois.verisign-grs.com'
    COMCAST = 'whois.nic.comcast'
    COMMBANK = 'whois.nic.commbank'
    COMMUNITY = 'whois.nic.community'
    COMPANY = 'whois.nic.company'
    COMPARE = 'whois.nic.compare'
    COMPUTER = 'whois.nic.computer'
    COMSEC = 'whois.nic.comsec'
    CONDOS = 'whois.nic.condos'
    CONSTRUCTION = 'whois.nic.construction'
    CONSULTING = 'whois.nic.consulting'
    CONTACT = 'whois.nic.contact'
    CONTRACTORS = 'whois.nic.contractors'
    COOKING = 'whois.nic.cooking'
    COOKINGCHANNEL = 'whois.nic.cookingchannel'
    COOL = 'whois.nic.cool'
    CORSICA = 'whois-corsica.nic.fr'
    COUNTRY = 'whois.uniregistry.net'
    COUPON = None
    COUPONS = 'whois.nic.coupons'
    COURSES = 'whois.nic.courses'
    CPA = 'whois.nic.cpa'
    CREDIT = 'whois.nic.credit'
    CREDITCARD = 'whois.nic.creditcard'
    CREDITUNION = 'whois.afilias-srs.net'
    CRICKET = 'whois.nic.cricket'
    CROWN = None
    CRS = None
    CRUISE = 'whois.nic.cruise'
    CRUISES = 'whois.nic.cruises'
    CSC = 'whois.nic.csc'
    CUISINELLA = 'whois.nic.cuisinella'
    CYMRU = 'whois.nic.cymru'
    CYOU = 'whois.nic.cyou'
    DABUR = 'whois.afilias-srs.net'
    DAD = 'whois.nic.google'
    DANCE = 'whois.nic.dance'
    DATA = 'whois.nic.data'
    DATE = 'whois.nic.date'
    DATING = 'whois.nic.dating'
    DATSUN = 'whois.nic.gmo'
    DAY = 'whois.nic.google'
    DCLK = 'whois.nic.google'
    DDS = 'whois.nic.dds'
    DEAL = 'whois.nic.deal'
    DEALER = 'whois.nic.dealer'
    DEALS = 'whois.nic.deals'
    DEGREE = 'whois.nic.degree'
    DELIVERY = 'whois.nic.delivery'
    DELL = None
    DELOITTE = 'whois.nic.deloitte'
    DELTA = 'whois.nic.delta'
    DEMOCRAT = 'whois.nic.democrat'
    DENTAL = 'whois.nic.dental'
    DENTIST = 'whois.nic.dentist'
    DESI = 'whois.nic.desi'
    DESIGN = 'whois.nic.design'
    DEV = 'whois.nic.google'
    DHL = None
    DIAMONDS = 'whois.nic.diamonds'
    DIET = 'whois.uniregistry.net'
    DIGITAL = 'whois.nic.digital'
    DIRECT = 'whois.nic.direct'
    DIRECTORY = 'whois.nic.directory'
    DISCOUNT = 'whois.nic.discount'
    DISCOVER = None
    DISH = 'whois.nic.dish'
    DIY = 'whois.nic.diy'
    DNP = 'whois.nic.dnp'
    DOCS = 'whois.nic.google'
    DOCTOR = 'whois.nic.doctor'
    DODGE = None
    DOG = 'whois.nic.dog'
    DOHA = None
    DOMAINS = 'whois.nic.domains'
    DOOSAN = None
    DOT = 'whois.nic.dot'
    DOWNLOAD = 'whois.nic.download'
    DRIVE = 'whois.nic.google'
    DTV = 'whois.nic.dtv'
    DUBAI = 'whois.nic.dubai'
    DUCK = 'whois.nic.duck'
    DUNLOP = 'whois.nic.dunlop'
    DUNS = None
    DUPONT = None
    DURBAN = 'durban-whois.registry.net.za'
    DVAG = 'whois.nic.dvag'
    DVR = 'whois.nic.dvr'
    EARTH = 'whois.nic.earth'
    EAT = 'whois.nic.google'
    ECO = 'whois.nic.eco'
    EDEKA = 'whois.afilias-srs.net'
    EDUCATION = 'whois.nic.education'
    EMAIL = 'whois.nic.email'
    EMERCK = 'whois.afilias-srs.net'
    ENERGY = 'whois.nic.energy'
    ENGINEER = 'whois.nic.engineer'
    ENGINEERING = 'whois.nic.engineering'
    ENTERPRISES = 'whois.nic.enterprises'
    EPOST = None
    EPSON = 'whois.nic.epson'
    EQUIPMENT = 'whois.nic.equipment'
    ERICSSON = 'whois.nic.ericsson'
    ERNI = 'whois.nic.erni'
    ESQ = 'whois.nic.google'
    ESTATE = 'whois.nic.estate'
    ESURANCE = None
    ETISALAT = 'whois.centralnic.com'
    EUROVISION = 'whois.nic.eurovision'
    EUS = 'whois.nic.eus'
    EVENTS = 'whois.nic.events'
    EVERBANK = None
    EXCHANGE = 'whois.nic.exchange'
    EXPERT = 'whois.nic.expert'
    EXPOSED = 'whois.nic.exposed'
    EXPRESS = 'whois.nic.express'
    EXTRASPACE = 'whois.afilias-srs.net'
    FAGE = 'whois.afilias-srs.net'
    FAIL = 'whois.nic.fail'
    FAIRWINDS = 'whois.nic.fairwinds'
    FAITH = 'whois.nic.faith'
    FAMILY = 'whois.nic.family'
    FAN = 'whois.nic.fan'
    FANS = 'whois.nic.fans'
    FARM = 'whois.nic.farm'
    FARMERS = None
    FASHION = 'whois.nic.fashion'
    FAST = 'whois.nic.fast'
    FEDEX = 'whois.nic.fedex'
    FEEDBACK = 'whois.nic.feedback'
    FERRARI = 'whois.nic.ferrari'
    FERRERO = None
    FIAT = 'whois.afilias-srs.net'
    FIDELITY = 'whois.nic.fidelity'
    FIDO = 'whois.afilias-srs.net'
    FILM = 'whois.nic.film'
    FINAL = 'whois.gtlds.nic.br'
    FINANCE = 'whois.nic.finance'
    FINANCIAL = 'whois.nic.financial'
    FIRE = 'whois.nic.fire'
    FIRESTONE = 'whois.nic.firestone'
    FIRMDALE = 'whois.nic.firmdale'
    FISH = 'whois.nic.fish'
    FISHING = 'whois.nic.fishing'
    FIT = 'whois.nic.fit'
    FITNESS = 'whois.nic.fitness'
    FLICKR = None
    FLIGHTS = 'whois.nic.flights'
    FLIR = None
    FLORIST = 'whois.nic.florist'
    FLOWERS = 'whois.uniregistry.net'
    FLSMIDTH = None
    FLY = 'whois.nic.google'
    FOO = 'whois.nic.google'
    FOOD = None
    FOODNETWORK = 'whois.nic.foodnetwork'
    FOOTBALL = 'whois.nic.football'
    FORD = None
    FOREX = 'whois.nic.forex'
    FORSALE = 'whois.nic.forsale'
    FORUM = 'whois.nic.forum'
    FOUNDATION = 'whois.nic.foundation'
    FOX = 'whois.nic.fox'
    FREE = 'whois.nic.free'
    FRESENIUS = 'whois.nic.fresenius'
    FRL = 'whois.nic.frl'
    FROGANS = 'whois.nic.frogans'
    FRONTDOOR = 'whois.nic.frontdoor'
    FRONTIER = None
    FTR = None
    FUJITSU = 'whois.nic.gmo'
    FUJIXEROX = 'whois.nic.fujixerox'
    FUN = 'whois.nic.fun'
    FUND = 'whois.nic.fund'
    FURNITURE = 'whois.nic.furniture'
    FUTBOL = 'whois.nic.futbol'
    FYI = 'whois.nic.fyi'
    GAL = 'whois.nic.gal'
    GALLERY = 'whois.nic.gallery'
    GALLO = 'whois.nic.gallo'
    GALLUP = 'whois.nic.gallup'
    GAME = 'whois.uniregistry.net'
    GAMES = 'whois.nic.games'
    GAP = None
    GARDEN = 'whois.nic.garden'
    GAY = 'whois.nic.gay'
    GBIZ = 'whois.nic.google'
    GDN = 'whois.nic.gdn'
    GEA = 'whois.nic.gea'
    GENT = 'whois.nic.gent'
    GENTING = 'whois.nic.genting'
    GEORGE = 'whois.nic.george'
    GGEE = 'whois.nic.ggee'
    GIFT = 'whois.uniregistry.net'
    GIFTS = 'whois.nic.gifts'
    GIVES = 'whois.nic.gives'
    GIVING = 'whois.nic.giving'
    GLADE = 'whois.nic.glade'
    GLASS = 'whois.nic.glass'
    GLE = 'whois.nic.google'
    GLOBAL = 'whois.nic.global'
    GLOBO = 'whois.gtlds.nic.br'
    GMAIL = 'whois.nic.google'
    GMBH = 'whois.nic.gmbh'
    GMO = 'whois.nic.gmo'
    GMX = 'whois.nic.gmx'
    GODADDY = 'whois.afilias-srs.net'
    GOLD = 'whois.nic.gold'
    GOLDPOINT = 'whois.nic.goldpoint'
    GOLF = 'whois.nic.golf'
    GOO = 'whois.nic.gmo'
    GOODHANDS = None
    GOODYEAR = 'whois.nic.goodyear'
    GOOG = 'whois.nic.google'
    GOOGLE = 'whois.nic.google'
    GOP = 'whois.nic.gop'
    GOT = 'whois.nic.got'
    GRAINGER = None
    GRAPHICS = 'whois.nic.graphics'
    GRATIS = 'whois.nic.gratis'
    GREEN = 'whois.afilias.net'
    GRIPE = 'whois.nic.gripe'
    GROUP = 'whois.nic.group'
    GUARDIAN = None
    GUCCI = None
    GUGE = 'whois.nic.google'
    GUIDE = 'whois.nic.guide'
    GUITARS = 'whois.uniregistry.net'
    GURU = 'whois.nic.guru'
    HAIR = 'whois.nic.hair'
    HAMBURG = 'whois.nic.hamburg'
    HANGOUT = 'whois.nic.google'
    HAUS = 'whois.nic.haus'
    HBO = None
    HDFC = 'whois.nic.hdfc'
    HDFCBANK = 'whois.nic.hdfcbank'
    HEALTH = None
    HEALTHCARE = 'whois.nic.healthcare'
    HELP = 'whois.uniregistry.net'
    HELSINKI = 'whois.nic.helsinki'
    HERE = 'whois.nic.google'
    HERMES = 'whois.afilias-srs.net'
    HGTV = 'whois.nic.hgtv'
    HIPHOP = 'whois.uniregistry.net'
    HISAMITSU = 'whois.nic.gmo'
    HITACHI = 'whois.nic.gmo'
    HIV = 'whois.uniregistry.net'
    HKT = 'whois.nic.hkt'
    HOCKEY = 'whois.nic.hockey'
    HOLDINGS = 'whois.nic.holdings'
    HOLIDAY = 'whois.nic.holiday'
    HOMEDEPOT = 'whois.nic.homedepot'
    HOMEGOODS = None
    HOMES = 'whois.afilias-srs.net'
    HOMESENSE = None
    HONDA = 'whois.nic.honda'
    HONEYWELL = None
    HORSE = 'whois.nic.horse'
    HOSPITAL = 'whois.nic.hospital'
    HOST = 'whois.nic.host'
    HOSTING = 'whois.uniregistry.net'
    HOT = 'whois.nic.hot'
    HOTELES = None
    HOTELS = None
    HOTMAIL = None
    HOUSE = 'whois.nic.house'
    HOW = 'whois.nic.google'
    HSBC = None
    HTC = None
    HUGHES = 'whois.nic.hughes'
    HYATT = None
    HYUNDAI = 'whois.nic.hyundai'
    IBM = 'whois.nic.ibm'
    ICBC = 'whois.nic.icbc'
    ICE = 'whois.nic.ice'
    ICU = 'whois.nic.icu'
    IEEE = None
    IFM = 'whois.nic.ifm'
    IINET = None
    IKANO = 'whois.nic.ikano'
    IMAMAT = 'whois.afilias-srs.net'
    IMDB = 'whois.nic.imdb'
    IMMO = 'whois.nic.immo'
    IMMOBILIEN = 'whois.nic.immobilien'
    INDUSTRIES = 'whois.nic.industries'
    INFINITI = 'whois.nic.gmo'
    INFO = 'whois.afilias.net'
    ING = 'whois.nic.google'
    INK = 'whois.nic.ink'
    INSTITUTE = 'whois.nic.institute'
    INSURANCE = 'whois.nic.insurance'
    INSURE = 'whois.nic.insure'
    INTEL = None
    INTERNATIONAL = 'whois.nic.international'
    INTUIT = None
    INVESTMENTS = 'whois.nic.investments'
    IPIRANGA = None
    IRISH = 'whois.nic.irish'
    ISELECT = None
    ISMAILI = 'whois.afilias-srs.net'
    IST = 'whois.afilias-srs.net'
    ISTANBUL = 'whois.afilias-srs.net'
    ITAU = None
    ITV = 'whois.afilias-srs.net'
    IVECO = 'whois.nic.iveco'
    IWC = None
    JAGUAR = 'whois.nic.jaguar'
    JAVA = 'whois.nic.java'
    JCB = 'whois.nic.gmo'
    JCP = None
    JEEP = 'whois.afilias-srs.net'
    JETZT = 'whois.nic.jetzt'
    JEWELRY = 'whois.nic.jewelry'
    JIO = 'whois.nic.jio'
    JLC = None
    JLL = 'whois.afilias-srs.net'
    JMP = None
    JNJ = None
    JOBURG = 'joburg-whois.registry.net.za'
    JOT = 'whois.nic.jot'
    JOY = 'whois.nic.joy'
    JPMORGAN = None
    JPRS = None
    JUEGOS = 'whois.uniregistry.net'
    JUNIPER = 'whois.nic.juniper'
    KAUFEN = 'whois.nic.kaufen'
    KDDI = 'whois.nic.kddi'
    KERRYHOTELS = 'whois.nic.kerryhotels'
    KERRYLOGISTICS = 'whois.nic.kerrylogistics'
    KERRYPROPERTIES = 'whois.nic.kerryproperties'
    KFH = 'whois.nic.kfh'
    KIA = 'whois.nic.kia'
    KIM = 'whois.afilias.net'
    KINDER = None
    KINDLE = 'whois.nic.kindle'
    KITCHEN = 'whois.nic.kitchen'
    KIWI = 'whois.nic.kiwi'
    KOELN = 'whois.ryce-rsp.com'
    KOMATSU = 'whois.nic.komatsu'
    KOSHER = 'whois.nic.kosher'
    KPMG = None
    KPN = None
    KRD = 'whois.nic.krd'
    KRED = None
    KUOKGROUP = 'whois.nic.kuokgroup'
    KYOTO = 'whois.nic.kyoto'
    LACAIXA = 'whois.nic.lacaixa'
    LADBROKES = None
    LAMBORGHINI = 'whois.afilias-srs.net'
    LAMER = 'whois.nic.lamer'
    LANCASTER = 'whois.nic.lancaster'
    LANCIA = 'whois.afilias-srs.net'
    LANCOME = None
    LAND = 'whois.nic.land'
    LANDROVER = 'whois.nic.landrover'
    LANXESS = None
    LASALLE = 'whois.afilias-srs.net'
    LAT = 'whois.nic.lat'
    LATINO = 'whois.nic.latino'
    LATROBE = 'whois.nic.latrobe'
    LAW = 'whois.nic.law'
    LAWYER = 'whois.nic.lawyer'
    LDS = 'whois.nic.lds'
    LEASE = 'whois.nic.lease'
    LECLERC = 'whois-leclerc.nic.fr'
    LEFRAK = 'whois.nic.lefrak'
    LEGAL = 'whois.nic.legal'
    LEGO = 'whois.nic.lego'
    LEXUS = 'whois.nic.lexus'
    LGBT = 'whois.afilias.net'
    LIAISON = None
    LIDL = 'whois.nic.lidl'
    LIFE = 'whois.nic.life'
    LIFEINSURANCE = None
    LIFESTYLE = 'whois.nic.lifestyle'
    LIGHTING = 'whois.nic.lighting'
    LIKE = 'whois.nic.like'
    LILLY = None
    LIMITED = 'whois.nic.limited'
    LIMO = 'whois.nic.limo'
    LINCOLN = None
    LINDE = 'whois.nic.linde'
    LINK = 'whois.uniregistry.net'
    LIPSY = 'whois.nic.lipsy'
    LIVE = 'whois.nic.live'
    LIVING = None
    LIXIL = 'whois.nic.lixil'
    LOAN = 'whois.nic.loan'
    LOANS = 'whois.nic.loans'
    LOCKER = 'whois.nic.locker'
    LOCUS = 'whois.nic.locus'
    LOFT = None
    LOL = 'whois.uniregistry.net'
    LONDON = 'whois.nic.london'
    LOTTE = 'whois.nic.lotte'
    LOTTO = 'whois.afilias.net'
    LOVE = 'whois.nic.love'
    LPL = 'whois.nic.lpl'
    LPLFINANCIAL = 'whois.nic.lplfinancial'
    LTD = 'whois.nic.ltd'
    LTDA = 'whois.afilias-srs.net'
    LUNDBECK = 'whois.nic.lundbeck'
    LUPIN = None
    LUXE = 'whois.nic.luxe'
    LUXURY = 'whois.nic.luxury'
    MACYS = 'whois.nic.macys'
    MADRID = 'whois.nic.madrid'
    MAIF = None
    MAISON = 'whois.nic.maison'
    MAKEUP = 'whois.nic.makeup'
    MAN = 'whois.nic.man'
    MANAGEMENT = 'whois.nic.management'
    MANGO = 'whois.nic.mango'
    MARKET = 'whois.nic.market'
    MARKETING = 'whois.nic.marketing'
    MARKETS = 'whois.nic.markets'
    MARRIOTT = 'whois.afilias-srs.net'
    MARSHALLS = None
    MASERATI = 'whois.nic.maserati'
    MATTEL = None
    MBA = 'whois.nic.mba'
    MCD = None
    MCDONALDS = None
    MCKINSEY = 'whois.nic.mckinsey'
    MED = 'whois.nic.med'
    MEDIA = 'whois.nic.media'
    MEET = 'whois.nic.google'
    MELBOURNE = 'whois.nic.melbourne'
    MEME = 'whois.nic.google'
    MEMORIAL = 'whois.nic.memorial'
    MEN = 'whois.nic.men'
    MENU = 'whois.nic.menu'
    MEO = None
    METLIFE = None
    MIAMI = 'whois.nic.miami'
    MICROSOFT = None
    MINI = 'whois.nic.mini'
    MINT = None
    MIT = 'whois.afilias-srs.net'
    MITSUBISHI = 'whois.nic.gmo'
    MLB = None
    MLS = 'whois.nic.mls'
    MMA = 'whois.nic.mma'
    MOBILE = 'whois.nic.mobile'
    MOBILY = None
    MODA = 'whois.nic.moda'
    MOE = 'whois.nic.moe'
    MOI = 'whois.nic.moi'
    MOM = 'whois.uniregistry.net'
    MONASH = 'whois.nic.monash'
    MONEY = 'whois.nic.money'
    MONSTER = 'whois.nic.monster'
    MONTBLANC = None
    MOPAR = None
    MORMON = 'whois.nic.mormon'
    MORTGAGE = 'whois.nic.mortgage'
    MOSCOW = 'whois.nic.moscow'
    MOTO = None
    MOTORCYCLES = 'whois.afilias-srs.net'
    MOV = 'whois.nic.google'
    MOVIE = 'whois.nic.movie'
    MOVISTAR = None
    MSD = None
    MTN = 'whois.nic.mtn'
    MTPC = None
    MTR = 'whois.nic.mtr'
    MUTUAL = None
    MUTUELLE = None
    NAB = 'whois.nic.nab'
    NADEX = None
    NAGOYA = 'whois.nic.nagoya'
    NATIONWIDE = 'whois.nic.nationwide'
    NATURA = 'whois.gtlds.nic.br'
    NAVY = 'whois.nic.navy'
    NBA = None
    NEC = 'whois.nic.nec'
    NET = 'whois.verisign-grs.com'
    NETBANK = 'whois.nic.netbank'
    NETFLIX = None
    NETWORK = 'whois.nic.network'
    NEUSTAR = None
    NEW = 'whois.nic.google'
    NEWHOLLAND = None
    NEWS = 'whois.nic.news'
    NEXT = 'whois.nic.next'
    NEXTDIRECT = 'whois.nic.nextdirect'
    NEXUS = 'whois.nic.google'
    NFL = None
    NGO = 'whois.publicinterestregistry.net'
    NHK = 'whois.nic.nhk'
    NICO = 'whois.nic.nico'
    NIKE = None
    NIKON = 'whois.nic.nikon'
    NINJA = 'whois.nic.ninja'
    NISSAN = 'whois.nic.gmo'
    NISSAY = 'whois.nic.nissay'
    NOKIA = 'whois.afilias-srs.net'
    NORTHWESTERNMUTUAL = None
    NORTON = 'whois.nic.norton'
    NOW = 'whois.nic.now'
    NOWRUZ = 'whois.nic.nowruz'
    NOWTV = 'whois.nic.nowtv'
    NRA = 'whois.afilias-srs.net'
    NRW = 'whois.nic.nrw'
    NTT = None
    NYC = None
    OBI = 'whois.nic.obi'
    OBSERVER = 'whois.nic.observer'
    OFF = 'whois.nic.off'
    OFFICE = None
    OKINAWA = 'whois.nic.okinawa'
    OLAYAN = 'whois.nic.olayan'
    OLAYANGROUP = 'whois.nic.olayangroup'
    OLDNAVY = None
    OLLO = 'whois.nic.ollo'
    OMEGA = 'whois.nic.omega'
    ONE = 'whois.nic.one'
    ONG = 'whois.publicinterestregistry.net'
    ONL = 'whois.afilias-srs.net'
    ONLINE = 'whois.nic.online'
    ONYOURSIDE = 'whois.nic.onyourside'
    OOO = 'whois.nic.ooo'
    OPEN = None
    ORACLE = 'whois.nic.oracle'
    ORANGE = 'whois.nic.orange'
    ORG = 'whois.pir.org'
    ORGANIC = 'whois.afilias.net'
    ORIENTEXPRESS = None
    ORIGINS = 'whois.nic.origins'
    OSAKA = 'whois.nic.osaka'
    OTSUKA = 'whois.nic.otsuka'
    OTT = 'whois.nic.ott'
    OVH = 'whois-ovh.nic.fr'
    PAGE = 'whois.nic.google'
    PAMPEREDCHEF = None
    PANASONIC = 'whois.nic.gmo'
    PANERAI = None
    PARIS = 'whois-paris.nic.fr'
    PARS = 'whois.nic.pars'
    PARTNERS = 'whois.nic.partners'
    PARTS = 'whois.nic.parts'
    PARTY = 'whois.nic.party'
    PASSAGENS = None
    PAY = 'whois.nic.pay'
    PCCW = 'whois.nic.pccw'
    PET = 'whois.afilias.net'
    PFIZER = None
    PHARMACY = 'whois.nic.pharmacy'
    PHILIPS = 'whois.nic.philips'
    PHONE = 'whois.nic.phone'
    PHOTO = 'whois.uniregistry.net'
    PHOTOGRAPHY = 'whois.nic.photography'
    PHOTOS = 'whois.nic.photos'
    PHYSIO = 'whois.nic.physio'
    PIAGET = None
    PICS = 'whois.uniregistry.net'
    PICTET = None
    PICTURES = 'whois.nic.pictures'
    PID = 'whois.nic.pid'
    PIN = 'whois.nic.pin'
    PING = None
    PINK = 'whois.afilias.net'
    PIONEER = 'whois.nic.gmo'
    PIZZA = 'whois.nic.pizza'
    PLACE = 'whois.nic.place'
    PLAY = 'whois.nic.google'
    PLAYSTATION = 'whois.nic.playstation'
    PLUMBING = 'whois.nic.plumbing'
    PLUS = 'whois.nic.plus'
    PNC = 'whois.nic.pnc'
    POHL = 'whois.nic.pohl'
    POKER = 'whois.afilias.net'
    POLITIE = 'whois.nic.politie'
    PORN = 'whois.registrar.adult'
    PRAMERICA = None
    PRAXI = None
    PRESS = 'whois.nic.press'
    PRIME = 'whois.nic.prime'
    PROD = 'whois.nic.google'
    PRODUCTIONS = 'whois.nic.productions'
    PROF = 'whois.nic.google'
    PROGRESSIVE = 'whois.afilias-srs.net'
    PROMO = 'whois.afilias.net'
    PROPERTIES = 'whois.nic.properties'
    PROPERTY = 'whois.uniregistry.net'
    PROTECTION = 'whois.nic.protection'
    PRU = None
    PRUDENTIAL = None
    PUB = 'whois.nic.pub'
    PWC = 'whois.afilias-srs.net'
    QPON = 'whois.nic.qpon'
    QUEBEC = 'whois.nic.quebec'
    QUEST = 'whois.nic.quest'
    QVC = None
    RACING = 'whois.nic.racing'
    RADIO = 'whois.nic.radio'
    RAID = 'whois.nic.raid'
    READ = 'whois.nic.read'
    REALESTATE = 'whois.nic.realestate'
    REALTOR = None
    REALTY = 'whois.nic.realty'
    RECIPES = 'whois.nic.recipes'
    RED = 'whois.afilias.net'
    REDSTONE = 'whois.nic.redstone'
    REDUMBRELLA = 'whois.afilias-srs.net'
    REHAB = 'whois.nic.rehab'
    REISE = 'whois.nic.reise'
    REISEN = 'whois.nic.reisen'
    REIT = 'whois.nic.reit'
    RELIANCE = 'whois.nic.reliance'
    REN = 'whois.nic.ren'
    RENT = 'whois.nic.rent'
    RENTALS = 'whois.nic.rentals'
    REPAIR = 'whois.nic.repair'
    REPORT = 'whois.nic.report'
    REPUBLICAN = 'whois.nic.republican'
    REST = 'whois.nic.rest'
    RESTAURANT = 'whois.nic.restaurant'
    REVIEW = 'whois.nic.review'
    REVIEWS = 'whois.nic.reviews'
    REXROTH = 'whois.nic.rexroth'
    RICH = 'whois.afilias-srs.net'
    RICHARDLI = 'whois.nic.richardli'
    RICOH = 'whois.nic.ricoh'
    RIGHTATHOME = None
    RIL = 'whois.nic.ril'
    RIO = 'whois.gtlds.nic.br'
    RIP = 'whois.nic.rip'
    RMIT = 'whois.nic.rmit'
    ROCHER = None
    ROCKS = 'whois.nic.rocks'
    RODEO = 'whois.nic.rodeo'
    ROGERS = 'whois.afilias-srs.net'
    ROOM = 'whois.nic.room'
    RSVP = 'whois.nic.google'
    RUGBY = 'whois.nic.rugby'
    RUHR = 'whois.nic.ruhr'
    RUN = 'whois.nic.run'
    RWE = 'whois.nic.rwe'
    RYUKYU = 'whois.nic.ryukyu'
    SAARLAND = 'whois.nic.saarland'
    SAFE = 'whois.nic.safe'
    SAFETY = None
    SAKURA = None
    SALE = 'whois.nic.sale'
    SALON = 'whois.nic.salon'
    SAMSCLUB = 'whois.nic.samsclub'
    SAMSUNG = 'whois.nic.samsung'
    SANDVIK = 'whois.nic.sandvik'
    SANDVIKCOROMANT = 'whois.nic.sandvikcoromant'
    SANOFI = 'whois.nic.sanofi'
    SAP = 'whois.nic.sap'
    SAPO = None
    SARL = 'whois.nic.sarl'
    SAS = None
    SAVE = 'whois.nic.save'
    SAXO = 'whois.nic.saxo'
    SBI = 'whois.nic.sbi'
    SBS = 'whois.nic.sbs'
    SCA = 'whois.nic.sca'
    SCB = 'whois.nic.scb'
    SCHAEFFLER = 'whois.afilias-srs.net'
    SCHMIDT = 'whois.nic.schmidt'
    SCHOLARSHIPS = 'whois.nic.scholarships'
    SCHOOL = 'whois.nic.school'
    SCHULE = 'whois.nic.schule'
    SCHWARZ = 'whois.nic.schwarz'
    SCIENCE = 'whois.nic.science'
    SCJOHNSON = 'whois.nic.scjohnson'
    SCOR = None
    SCOT = 'whois.nic.scot'
    SEAT = 'whois.nic.seat'
    SECURE = 'whois.nic.secure'
    SECURITY = 'whois.nic.security'
    SEEK = 'whois.nic.seek'
    SELECT = 'whois.nic.select'
    SENER = None
    SERVICES = 'whois.nic.services'
    SES = 'whois.nic.ses'
    SEVEN = 'whois.nic.seven'
    SEW = 'whois.afilias-srs.net'
    SEX = 'whois.registrar.adult'
    SEXY = 'whois.uniregistry.net'
    SFR = 'whois.nic.sfr'
    SHANGRILA = 'whois.nic.shangrila'
    SHARP = 'whois.nic.gmo'
    SHAW = 'whois.afilias-srs.net'
    SHELL = 'whois.nic.shell'
    SHIA = 'whois.nic.shia'
    SHIKSHA = 'whois.afilias.net'
    SHOES = 'whois.nic.shoes'
    SHOP = 'whois.nic.shop'
    SHOPPING = 'whois.nic.shopping'
    SHOUJI = 'whois.teleinfo.cn'
    SHOW = 'whois.nic.show'
    SHOWTIME = 'whois.afilias-srs.net'
    SHRIRAM = None
    SILK = 'whois.nic.silk'
    SINA = 'whois.nic.sina'
    SINGLES = 'whois.nic.singles'
    SITE = 'whois.nic.site'
    SKI = 'whois.afilias.net'
    SKIN = 'whois.nic.skin'
    SKY = 'whois.nic.sky'
    SKYPE = None
    SLING = 'whois.nic.sling'
    SMART = 'whois.nic.smart'
    SMILE = 'whois.nic.smile'
    SNCF = 'whois.nic.sncf'
    SOCCER = 'whois.nic.soccer'
    SOCIAL = 'whois.nic.social'
    SOFTBANK = 'whois.nic.softbank'
    SOFTWARE = 'whois.nic.software'
    SOHU = None
    SOLAR = 'whois.nic.solar'
    SOLUTIONS = 'whois.nic.solutions'
    SONG = None
    SONY = 'whois.nic.sony'
    SOY = 'whois.nic.google'
    SPACE = 'whois.nic.space'
    SPIEGEL = None
    SPOT = 'whois.nic.spot'
    SPREADBETTING = 'whois.nic.spreadbetting'
    SRL = 'whois.afilias-srs.net'
    SRT = None
    STADA = 'whois.afilias-srs.net'
    STAPLES = None
    STAR = 'whois.nic.star'
    STARHUB = None
    STATEBANK = 'whois.nic.statebank'
    STATEFARM = None
    STATOIL = None
    STC = 'whois.nic.stc'
    STCGROUP = 'whois.nic.stcgroup'
    STOCKHOLM = 'whois.afilias-srs.net'
    STORAGE = 'whois.nic.storage'
    STORE = 'whois.nic.store'
    STREAM = 'whois.nic.stream'
    STUDIO = 'whois.nic.studio'
    STUDY = 'whois.nic.study'
    STYLE = 'whois.nic.style'
    SUCKS = 'whois.nic.sucks'
    SUPPLIES = 'whois.nic.supplies'
    SUPPLY = 'whois.nic.supply'
    SUPPORT = 'whois.nic.support'
    SURF = 'whois.nic.surf'
    SURGERY = 'whois.nic.surgery'
    SUZUKI = 'whois.nic.suzuki'
    SWATCH = 'whois.nic.swatch'
    SWIFTCOVER = None
    SWISS = 'whois.nic.swiss'
    SYDNEY = 'whois.nic.sydney'
    SYMANTEC = None
    SYSTEMS = 'whois.nic.systems'
    TAB = 'whois.nic.tab'
    TAIPEI = 'whois.nic.taipei'
    TALK = 'whois.nic.talk'
    TAOBAO = None
    TARGET = None
    TATAMOTORS = 'whois.nic.tatamotors'
    TATAR = 'whois.nic.tatar'
    TATTOO = 'whois.uniregistry.net'
    TAX = 'whois.nic.tax'
    TAXI = 'whois.nic.taxi'
    TCI = 'whois.nic.tci'
    TDK = 'whois.nic.tdk'
    TEAM = 'whois.nic.team'
    TECH = 'whois.nic.tech'
    TECHNOLOGY = 'whois.nic.technology'
    TELECITY = None
    TELEFONICA = None
    TEMASEK = 'whois.afilias-srs.net'
    TENNIS = 'whois.nic.tennis'
    TEVA = 'whois.nic.teva'
    THD = 'whois.nic.thd'
    THEATER = 'whois.nic.theater'
    THEATRE = 'whois.nic.theatre'
    TIAA = 'whois.nic.tiaa'
    TICKETS = 'whois.nic.tickets'
    TIENDA = 'whois.nic.tienda'
    TIFFANY = 'whois.nic.tiffany'
    TIPS = 'whois.nic.tips'
    TIRES = 'whois.nic.tires'
    TIROL = 'whois.nic.tirol'
    TJMAXX = None
    TJX = None
    TKMAXX = None
    TMALL = None
    TODAY = 'whois.nic.today'
    TOKYO = 'whois.nic.tokyo'
    TOOLS = 'whois.nic.tools'
    TOP = 'whois.nic.top'
    TORAY = 'whois.nic.toray'
    TOSHIBA = 'whois.nic.toshiba'
    TOTAL = 'whois.nic.total'
    TOURS = 'whois.nic.tours'
    TOWN = 'whois.nic.town'
    TOYOTA = 'whois.nic.toyota'
    TOYS = 'whois.nic.toys'
    TRADE = 'whois.nic.trade'
    TRADING = 'whois.nic.trading'
    TRAINING = 'whois.nic.training'
    TRAVELCHANNEL = 'whois.nic.travelchannel'
    TRAVELERS = 'whois.afilias-srs.net'
    TRAVELERSINSURANCE = 'whois.afilias-srs.net'
    TRUST = 'whois.nic.trust'
    TRV = 'whois.afilias-srs.net'
    TUBE = None
    TUI = 'whois.nic.tui'
    TUNES = 'whois.nic.tunes'
    TUSHU = 'whois.nic.tushu'
    TVS = 'whois.nic.tvs'
    UBANK = 'whois.nic.ubank'
    UBS = 'whois.nic.ubs'
    UCONNECT = None
    UNICOM = 'whois.nic.unicom'
    UNIVERSITY = 'whois.nic.university'
    UNO = 'whois.nic.uno'
    UOL = 'whois.gtlds.nic.br'
    UPS = 'whois.nic.ups'
    VACATIONS = 'whois.nic.vacations'
    VANA = 'whois.nic.vana'
    VANGUARD = 'whois.nic.vanguard'
    VEGAS = 'whois.afilias-srs.net'
    VENTURES = 'whois.nic.ventures'
    VERISIGN = 'whois.nic.verisign'
    VERSICHERUNG = 'whois.nic.versicherung'
    VET = 'whois.nic.vet'
    VIAJES = 'whois.nic.viajes'
    VIDEO = 'whois.nic.video'
    VIG = 'whois.afilias-srs.net'
    VIKING = 'whois.afilias-srs.net'
    VILLAS = 'whois.nic.villas'
    VIN = 'whois.nic.vin'
    VIP = 'whois.nic.vip'
    VIRGIN = 'whois.nic.virgin'
    VISA = 'whois.nic.visa'
    VISION = 'whois.nic.vision'
    VISTA = None
    VISTAPRINT = None
    VIVA = 'whois.nic.viva'
    VIVO = None
    VLAANDEREN = 'whois.nic.vlaanderen'
    VODKA = 'whois.nic.vodka'
    VOLKSWAGEN = 'whois.afilias-srs.net'
    VOLVO = 'whois.nic.volvo'
    VOTE = 'whois.afilias.net'
    VOTING = 'whois.nic.voting'
    VOTO = 'whois.afilias.net'
    VOYAGE = 'whois.nic.voyage'
    VUELOS = None
    WALES = 'whois.nic.wales'
    WALMART = 'whois.nic.walmart'
    WALTER = 'whois.nic.walter'
    WANG = 'whois.gtld.knet.cn'
    WANGGOU = 'whois.nic.wanggou'
    WARMAN = None
    WATCH = 'whois.nic.watch'
    WATCHES = 'whois.nic.watches'
    WEATHER = None
    WEATHERCHANNEL = None
    WEBCAM = 'whois.nic.webcam'
    WEBER = 'whois.nic.weber'
    WEBSITE = 'whois.nic.website'
    WED = 'whois.nic.wed'
    WEDDING = 'whois.nic.wedding'
    WEIBO = 'whois.nic.weibo'
    WEIR = None
    WHOSWHO = 'whois.nic.whoswho'
    WIEN = 'whois.nic.wien'
    WIKI = 'whois.nic.wiki'
    WILLIAMHILL = None
    WIN = 'whois.nic.win'
    WINDOWS = None
    WINE = 'whois.nic.wine'
    WINNERS = None
    WME = 'whois.nic.wme'
    WOLTERSKLUWER = 'whois.nic.wolterskluwer'
    WOODSIDE = 'whois.nic.woodside'
    WORK = 'whois.nic.work'
    WORKS = 'whois.nic.works'
    WORLD = 'whois.nic.world'
    WOW = 'whois.nic.wow'
    WTC = 'whois.nic.wtc'
    WTF = 'whois.nic.wtf'
    XBOX = None
    XEROX = 'whois.nic.xerox'
    XFINITY = 'whois.nic.xfinity'
    XIHUAN = 'whois.teleinfo.cn'
    XIN = 'whois.nic.xin'
    XN__11B4C3D = 'whois.nic.xn--11b4c3d'
    XN__1CK2E1B = None
    XN__1QQW23A = 'whois.ngtld.cn'
    XN__30RR7Y = 'whois.gtld.knet.cn'
    XN__3BST00M = 'whois.gtld.knet.cn'
    XN__3DS443G = 'whois.teleinfo.cn'
    XN__3OQ18VL8PN36A = 'whois.nic.xn--3oq18vl8pn36a'
    XN__3PXU8K = 'whois.nic.xn--3pxu8k'
    XN__42C2D9A = 'whois.nic.xn--42c2d9a'
    XN__45Q11C = 'whois.nic.xn--45q11c'
    XN__4GBRIM = 'whois.afilias-srs.net'
    XN__55QW42G = 'whois.conac.cn'
    XN__55QX5D = 'whois.ngtld.cn'
    XN__5SU34J936BGSG = 'whois.nic.xn--5su34j936bgsg'
    XN__5TZM5G = 'whois.nic.xn--5tzm5g'
    XN__6FRZ82G = 'whois.afilias.net'
    XN__6QQ986B3XL = 'whois.gtld.knet.cn'
    XN__80ADXHKS = 'whois.nic.xn--80adxhks'
    XN__80AQECDR1A = 'whois.nic.xn--80aqecdr1a'
    XN__80ASEHDB = 'whois.nic.xn--80asehdb'
    XN__80ASWG = 'whois.nic.xn--80aswg'
    XN__8Y0A063A = 'whois.nic.xn--8y0a063a'
    XN__9DBQ2A = 'whois.nic.xn--9dbq2a'
    XN__9ET52U = 'whois.gtld.knet.cn'
    XN__9KRT00A = 'whois.nic.xn--9krt00a'
    XN__B4W605FERD = 'whois.afilias-srs.net'
    XN__BCK1B9A5DRE4C = None
    XN__C1AVG = 'whois.publicinterestregistry.net'
    XN__C2BR7G = 'whois.nic.xn--c2br7g'
    XN__CCK2B3B = None
    XN__CG4BKI = 'whois.kr'
    XN__CZR694B = None
    XN__CZRS0T = 'whois.nic.xn--czrs0t'
    XN__CZRU2D = 'whois.gtld.knet.cn'
    XN__D1ACJ3B = 'whois.nic.xn--d1acj3b'
    XN__ECKVDTC9D = None
    XN__EFVY88H = 'whois.nic.xn--efvy88h'
    XN__ESTV75G = None
    XN__FCT429K = None
    XN__FHBEI = 'whois.nic.xn--fhbei'
    XN__FIQ228C5HS = 'whois.teleinfo.cn'
    XN__FIQ64B = 'whois.gtld.knet.cn'
    XN__FJQ720A = 'whois.nic.xn--fjq720a'
    XN__FLW351E = 'whois.nic.google'
    XN__FZYS8D69UVGM = 'whois.nic.xn--fzys8d69uvgm'
    XN__G2XX48C = None
    XN__GCKR3F0F = None
    XN__GK3AT1E = None
    XN__HXT814E = 'whois.nic.xn--hxt814e'
    XN__I1B6B1A6A2E = 'whois.publicinterestregistry.net'
    XN__IMR513N = None
    XN__IO0A7I = 'whois.ngtld.cn'
    XN__J1AEF = 'whois.nic.xn--j1aef'
    XN__JLQ61U9W7B = 'whois.nic.xn--jlq61u9w7b'
    XN__JVR189M = None
    XN__KCRX77D1X4A = 'whois.nic.xn--kcrx77d1x4a'
    XN__KPU716F = None
    XN__KPUT3I = 'whois.nic.xn--kput3i'
    XN__MGBA3A3EJT = None
    XN__MGBA7C0BBN0A = 'whois.nic.xn--mgba7c0bbn0a'
    XN__MGBAB2BD = 'whois.nic.xn--mgbab2bd'
    XN__MGBB9FBPOB = None
    XN__MGBCA7DZDO = 'whois.nic.xn--mgbca7dzdo'
    XN__MGBI4ECEXP = 'whois.nic.xn--mgbi4ecexp'
    XN__MGBT3DHD = 'whois.nic.xn--mgbt3dhd'
    XN__MK1BU44C = 'whois.nic.xn--mk1bu44c'
    XN__MXTQ1M = 'whois.nic.xn--mxtq1m'
    XN__NGBC5AZD = 'whois.nic.xn--ngbc5azd'
    XN__NGBE9E0A = 'whois.nic.xn--ngbe9e0a'
    XN__NQV7F = 'whois.publicinterestregistry.net'
    XN__NQV7FS00EMA = 'whois.nic.xn--nqv7fs00ema'
    XN__NYQY26A = None
    XN__P1ACF = 'whois.nic.xn--p1acf'
    XN__PBT977C = None
    XN__PSSY2U = 'whois.nic.xn--pssy2u'
    XN__Q9JYB4C = 'whois.nic.google'
    XN__QCKA1PMC = 'whois.nic.google'
    XN__RHQV96G = None
    XN__ROVU88B = None
    XN__SES554G = 'whois.nic.xn--ses554g'
    XN__T60B56A = 'whois.nic.xn--t60b56a'
    XN__TCKWE = 'whois.nic.xn--tckwe'
    XN__TIQ49XQYJ = 'whois.nic.xn--tiq49xqyj'
    XN__UNUP4Y = 'whois.nic.xn--unup4y'
    XN__VERMGENSBERATER__CTB = 'whois.nic.xn--vermgensberater-ctb'
    XN__VERMGENSBERATUNG__PWB = 'whois.nic.xn--vermgensberatung-pwb'
    XN__VHQUV = 'whois.nic.xn--vhquv'
    XN__VUQ861B = 'whois.teleinfo.cn'
    XN__W4R85EL8FHU5DNRA = 'whois.nic.xn--w4r85el8fhu5dnra'
    XN__W4RS40L = 'whois.nic.xn--w4rs40l'
    XN__XHQ521B = 'whois.ngtld.cn'
    XN__ZFR164B = 'whois.conac.cn'
    XPERIA = None
    XYZ = 'whois.nic.xyz'
    YACHTS = 'whois.afilias-srs.net'
    YAHOO = None
    YAMAXUN = 'whois.nic.yamaxun'
    YANDEX = None
    YODOBASHI = 'whois.nic.gmo'
    YOGA = 'whois.nic.yoga'
    YOKOHAMA = 'whois.nic.yokohama'
    YOU = 'whois.nic.you'
    YOUTUBE = 'whois.nic.google'
    YUN = 'whois.teleinfo.cn'
    ZAPPOS = 'whois.nic.zappos'
    ZARA = 'whois.afilias-srs.net'
    ZERO = None
    ZIP = 'whois.nic.google'
    ZIPPO = None
    ZONE = 'whois.nic.zone'
    ZUERICH = 'whois.nic.zuerich'

    # generic-restricted
    BIZ = 'whois.nic.biz'
    NAME = 'whois.nic.name'
    PRO = 'whois.afilias.net'


class SponsoredTLD:
    AERO = 'whois.aero'
    ASIA = 'whois.nic.asia'
    CAT = 'whois.nic.cat'
    COOP = 'whois.nic.coop'
    EDU = 'whois.educause.edu'
    GOV = 'whois.dotgov.gov'
    INT = 'whois.iana.org'
    JOBS = 'whois.nic.jobs'
    MIL = None
    MOBI = 'whois.nic.mobi'
    MUSEUM = 'whois.nic.museum'
    POST = 'whois.dotpostregistry.net'
    TEL = 'whois.nic.tel'
    TRAVEL = 'whois.nic.travel'
    XXX = 'whois.registrar.adult'
