# 2024-04-18 00:00:01 by RouterOS 7.14.2
# software id = ####-####
#
# model = RB962UiGS-5HacT2HnT
# serial number = ############

/ip hotspot profile
set [ find default=yes ] html-directory=hotspot
add dns-name=192.168.10.1 hotspot-address=192.168.10.1 html-directory=\
    flash/hotspot login-by=mac mac-auth-password=\
    macauth name=hsprof1 radius-interim-update=30s \
    use-radius=yes

/ip pool
add name=hs-pool-12 ranges=192.168.10.2-192.168.10.254

/ip dhcp-server
add address-pool=hs-pool-12 interface=bridgehp lease-time=6h name=dhcp1

/ip hotspot
add address-pool=hs-pool-12 addresses-per-mac=1 disabled=no interface=\
    bridgehp keepalive-timeout=5m login-timeout=5s name=hotspot1 profile=\
    hsprof1

/interface bridge port
add bridge=bridgehp interface=wlan2

/ip address
add address=192.168.10.1/24 interface=bridgehp network=192.168.10.0

/ip firewall nat
add action=masquerade chain=srcnat comment="masquerade hotspot network" src-address=192.168.10.0/24

/ip hotspot walled-garden
add dst-host=auth.leshe4ka.ru server=hotspot1

/radius
add address=192.168.88.246 service=hotspot
