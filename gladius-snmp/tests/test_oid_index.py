"""OID index parsing for protocol-state walks."""
import pytest

import app

OSPF_NBR_STATE = "1.3.6.1.2.1.14.10.1.6"


@pytest.mark.parametrize("oid, expected", [
    # ospfNbrIpAddr (4 sub-ids) + ospfNbrAddressLessIndex (1 sub-id)
    (f"{OSPF_NBR_STATE}.10.0.12.2.0",      "10.0.12.2"),
    (f"{OSPF_NBR_STATE}.192.168.1.1.0",    "192.168.1.1"),
    (f"{OSPF_NBR_STATE}.172.16.255.254.0", "172.16.255.254"),
    # address-less neighbour: IP is 0.0.0.0, the ifIndex keeps it distinct
    (f"{OSPF_NBR_STATE}.0.0.0.0.7",        "0.0.0.0/7"),
])
def test_ospf_nbr_key(oid, expected):
    assert app._ospf_nbr_key(oid) == expected


def test_ospf_neighbours_sharing_last_three_octets_do_not_collide():
    a = app._ospf_nbr_key(f"{OSPF_NBR_STATE}.10.1.1.2.0")
    b = app._ospf_nbr_key(f"{OSPF_NBR_STATE}.11.1.1.2.0")
    assert a != b
    assert a == "10.1.1.2" and b == "11.1.1.2"
